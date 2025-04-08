package task

import (
	"encoding/json"
	"errors"
	"fmt"
	authApi "github.com/opengovern/og-util/pkg/api"
	"github.com/opengovern/og-util/pkg/es"
	"github.com/opengovern/og-util/pkg/httpclient"
	"github.com/opengovern/og-util/pkg/jq"
	"github.com/opengovern/og-util/pkg/opengovernance-es-sdk"
	og_es_sdk "github.com/opengovern/og-util/pkg/opengovernance-es-sdk"
	"github.com/opengovern/og-util/pkg/tasks"
	coreApi "github.com/opengovern/opensecurity/services/core/api"
	coreClient "github.com/opengovern/opensecurity/services/core/client"
	"github.com/opengovern/opensecurity/services/tasks/scheduler"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// --- Configuration ---

const (
	appName          = "nvd_lookup_enterprise"
	appVersion       = "2.3" // Incremented version
	nvdBaseURL       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	maxCLIInputCVEs  = 5
	maxJSONInputCVEs = 1000
	stdinIndicator   = "-"
)

// Default configuration values
const (
	defaultLogLevel             = "info"
	defaultMaxConcurrentFetches = 5
	defaultRequestTimeoutSec    = 25
	defaultMaxRetries           = 3
	defaultInitialBackoffSec    = 2
	defaultRateLimitRequests    = 45.0
	defaultRateLimitPeriodSec   = 30
)

var defaultMetricPriorities = map[string]int{"v4.0": 100, "v3.1": 90, "v2.0": 80}

// Regex for basic CVE ID format validation (case-insensitive flag added implicitly by ToLower)
var cveRegex = regexp.MustCompile(`^cve-\d{4}-\d{4,}$`) // Expect lowercase input now

// --- Configuration Struct & Variables ---
type Config struct {
	NvdApiKey            string         `mapstructure:"nvdApiKey"`
	LogLevel             string         `mapstructure:"logLevel"`
	MaxConcurrentFetches int            `mapstructure:"maxConcurrentFetches"`
	RequestTimeoutSec    int            `mapstructure:"requestTimeoutSec"`
	MaxRetries           int            `mapstructure:"maxRetries"`
	InitialBackoffSec    int            `mapstructure:"initialBackoffSec"`
	RateLimitRequests    float64        `mapstructure:"rateLimitRequests"`
	RateLimitPeriodSec   int            `mapstructure:"rateLimitPeriodSec"`
	MetricPriorities     map[string]int `mapstructure:"metricPriorities"`
}

var (
	cfg              Config                 // Holds loaded configuration
	logger           *slog.Logger           // Global structured logger
	httpClient       *http.Client           // Reusable HTTP client
	sortedPriorities []MetricPriorityConfig // Sorted priorities after validation
	userAgent        string                 // Dynamically set user agent
)

// --- Weighted Priority Config Struct ---
type MetricPriorityConfig struct {
	Version string
	Weight  int
}

// --- Input/Output Struct Definitions ---
// (Struct definitions are identical to the previous version)
type InputNVDResponse struct {
	Vulnerabilities []InputVulnerability `json:"vulnerabilities"`
}
type InputVulnerability struct {
	CVE InputCVE `json:"cve"`
}
type InputCVE struct {
	ID                    string             `json:"id"`
	SourceIdentifier      string             `json:"sourceIdentifier"`
	Published             string             `json:"published"`
	LastModified          string             `json:"lastModified"`
	VulnStatus            string             `json:"vulnStatus"`
	Descriptions          []InputDescription `json:"descriptions"`
	Metrics               InputMetrics       `json:"metrics"`
	Weaknesses            []InputWeakness    `json:"weaknesses"`
	CisaExploitAdd        string             `json:"cisaExploitAdd,omitempty"`
	CisaActionDue         string             `json:"cisaActionDue,omitempty"`
	CisaRequiredAction    string             `json:"cisaRequiredAction,omitempty"`
	CisaVulnerabilityName string             `json:"cisaVulnerabilityName,omitempty"`
}
type InputDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}
type InputMetrics struct {
	CvssMetricV40 []InputCvssMetricV40 `json:"cvssMetricV40,omitempty"`
	CvssMetricV31 []InputCvssMetricV31 `json:"cvssMetricV31,omitempty"`
	CvssMetricV2  []InputCvssMetricV2  `json:"cvssMetricV2,omitempty"`
}
type InputCvssMetricV40 struct {
	Source   string           `json:"source"`
	Type     string           `json:"type"`
	CvssData InputCvssDataV40 `json:"cvssData"`
}
type InputCvssDataV40 struct {
	Version                           string  `json:"version"`
	VectorString                      string  `json:"vectorString"`
	BaseScore                         float64 `json:"baseScore"`
	BaseSeverity                      string  `json:"baseSeverity"`
	AttackVector                      string  `json:"attackVector"`
	AttackComplexity                  string  `json:"attackComplexity"`
	AttackRequirements                string  `json:"attackRequirements"`
	PrivilegesRequired                string  `json:"privilegesRequired"`
	UserInteraction                   string  `json:"userInteraction"`
	VulnConfidentialityImpact         string  `json:"vulnConfidentialityImpact"`
	VulnIntegrityImpact               string  `json:"vulnIntegrityImpact"`
	VulnAvailabilityImpact            string  `json:"vulnAvailabilityImpact"`
	SubConfidentialityImpact          string  `json:"subConfidentialityImpact"`
	SubIntegrityImpact                string  `json:"subIntegrityImpact"`
	SubAvailabilityImpact             string  `json:"subAvailabilityImpact"`
	ExploitMaturity                   string  `json:"exploitMaturity"`
	ConfidentialityRequirement        string  `json:"confidentialityRequirement"`
	IntegrityRequirement              string  `json:"integrityRequirement"`
	AvailabilityRequirement           string  `json:"availabilityRequirement"`
	ModifiedAttackVector              string  `json:"modifiedAttackVector"`
	ModifiedAttackComplexity          string  `json:"modifiedAttackComplexity"`
	ModifiedAttackRequirements        string  `json:"modifiedAttackRequirements"`
	ModifiedPrivilegesRequired        string  `json:"modifiedPrivilegesRequired"`
	ModifiedUserInteraction           string  `json:"modifiedUserInteraction"`
	ModifiedVulnConfidentialityImpact string  `json:"modifiedVulnConfidentialityImpact"`
	ModifiedVulnIntegrityImpact       string  `json:"modifiedVulnIntegrityImpact"`
	ModifiedVulnAvailabilityImpact    string  `json:"modifiedVulnAvailabilityImpact"`
	ModifiedSubConfidentialityImpact  string  `json:"modifiedSubConfidentialityImpact"`
	ModifiedSubIntegrityImpact        string  `json:"modifiedSubIntegrityImpact"`
	ModifiedSubAvailabilityImpact     string  `json:"modifiedSubAvailabilityImpact"`
	Safety                            string  `json:"Safety"`
	Automatable                       string  `json:"Automatable"`
	Recovery                          string  `json:"Recovery"`
	ValueDensity                      string  `json:"valueDensity"`
	VulnerabilityResponseEffort       string  `json:"vulnerabilityResponseEffort"`
	ProviderUrgency                   string  `json:"providerUrgency"`
}
type InputCvssMetricV31 struct {
	Source              string           `json:"source"`
	Type                string           `json:"type"`
	CvssData            InputCvssDataV31 `json:"cvssData"`
	ExploitabilityScore float64          `json:"exploitabilityScore"`
	ImpactScore         float64          `json:"impactScore"`
}
type InputCvssDataV31 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}
type InputCvssMetricV2 struct {
	Source                  string          `json:"source"`
	Type                    string          `json:"type"`
	CvssData                InputCvssDataV2 `json:"cvssData"`
	BaseSeverity            string          `json:"baseSeverity"`
	ExploitabilityScore     float64         `json:"exploitabilityScore"`
	ImpactScore             float64         `json:"impactScore"`
	AcInsufInfo             bool            `json:"acInsufInfo"`
	ObtainAllPrivilege      bool            `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool            `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool            `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool            `json:"userInteractionRequired"`
}
type InputCvssDataV2 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
}
type InputWeakness struct {
	Source      string             `json:"source"`
	Type        string             `json:"type"`
	Description []InputDescription `json:"description"`
}

type OutputDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}
type OutputMetrics struct {
	CvssMetricV40 []InputCvssMetricV40 `json:"cvssMetricV40,omitempty"`
	CvssMetricV31 []InputCvssMetricV31 `json:"cvssMetricV31,omitempty"`
	CvssMetricV2  []InputCvssMetricV2  `json:"cvssMetricV2,omitempty"`
}
type OutputWeakness struct {
	Source      string              `json:"source"`
	Type        string              `json:"type"`
	Description []OutputDescription `json:"description"`
}

// Result struct for worker communication
type CVEProcessingResult struct {
	CVEID  string
	Output *OutputCVE
	Error  error
}

// --- Initialization ---

func init() {
	setupLoggerDefault()
	loadConfig()
	setupLoggerWithConfig()
	validateAndSortPriorities()
	setupHTTPClient()
	setUserAgent()
}

func RunTask(ctx context.Context, jq *jq.JobQueue, coreServiceEndpoint string, esClient opengovernance.Client, _ *zap.Logger, request tasks.TaskRequest, response *scheduler.TaskResponse) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var rawCveIDs []string
	var err error

	logger.Info("Fetching SBOMs for task")
	inventoryClient := coreClient.NewCoreServiceClient(coreServiceEndpoint)

	if queryID, ok := request.TaskDefinition.Params["query_id"].(string); ok && queryID != "" {
		rawCveIDs, err = GetVulnerabilitiesFromQueryID(ctx, inventoryClient, request.TaskDefinition.Params)
	} else if queryExec, ok := request.TaskDefinition.Params["query_to_execute"].(string); ok && queryExec != "" {
		rawCveIDs, err = GetVulnerabilitiesFromInlineQuery(ctx, inventoryClient, request.TaskDefinition.Params)
	} else {
		err = fmt.Errorf("SBOM source query not provided (missing 'query_id' or 'query_to_execute' in params)")
	}

	if err != nil {
		logger.Error("Failed to fetch SBOMs", zap.Error(err))
		return err
	}
	if len(rawCveIDs) == 0 {
		logger.Info("No cve found matching query.")
		response.Result = json.RawMessage(`{"sboms_done_number":0, "sboms_succeeded_number":0, "sboms":[]}`)
		return nil
	}

	logger.Info("Processing packages for artifacts", zap.Strings("cve_ids", rawCveIDs))

	logger = logger.With("app_version", appVersion)
	logger.Info("Application starting")

	apiKey := "3cdacd44-7beb-4282-b836-7ad567c68147"
	cveIDs := validateCVEInput(rawCveIDs)

	logger.Info("Processing validated CVE IDs", "count", len(cveIDs))

	limit := rate.Limit(cfg.RateLimitRequests / float64(cfg.RateLimitPeriodSec))
	limiter := rate.NewLimiter(limit, cfg.MaxConcurrentFetches)
	logger.Info("NVD rate limiter configured", slog.Float64("rate_per_sec", float64(limit)), slog.Int("burst", cfg.MaxConcurrentFetches))

	jobs := make(chan string, len(cveIDs))
	results := make(chan CVEProcessingResult, len(cveIDs))
	var wg sync.WaitGroup

	logger.Info("Starting worker goroutines", "count", cfg.MaxConcurrentFetches)
	for w := 1; w <= cfg.MaxConcurrentFetches; w++ {
		wg.Add(1)
		go worker(ctx, logger.With("worker_id", w), w, jobs, results, &wg, apiKey, limiter)
	}

	go func() {
		defer close(jobs)
		logger.Debug("Starting job submission")
		for _, cveID := range cveIDs {
			select {
			case jobs <- cveID:
				logger.Debug("Submitted job", "cve_id", cveID)
			case <-ctx.Done():
				logger.Warn("Context cancelled during job submission", "error", ctx.Err())
				return
			}
		}
		logger.Debug("Finished job submission")
	}()

	go func() {
		logger.Debug("Waiting for workers to finish...")
		wg.Wait()
		logger.Debug("All workers finished, closing results channel.")
		close(results)
	}()

	errorCount := processResults(ctx, esClient, request, results)

	logger.Info("Processing complete", "successful_count", len(cveIDs)-errorCount, "failed_count", errorCount)

	if errorCount > 0 {
		logger.Error("Completed with errors.")
	}
	logger.Info("Completed successfully.")
	return nil
}

// --- Setup Functions ---

func setupLoggerDefault() {
	opts := slog.HandlerOptions{Level: slog.LevelInfo}
	handler := slog.NewJSONHandler(os.Stderr, &opts)
	logger = slog.New(handler).With("app", appName)
	slog.SetDefault(logger)
}

func setupLoggerWithConfig() {
	var logLevel slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
		logger.Warn("Invalid logLevel in config, using default 'info'", "configured_level", cfg.LogLevel)
	}
	opts := slog.HandlerOptions{Level: logLevel}
	handler := slog.NewJSONHandler(os.Stderr, &opts)
	logger = slog.New(handler).With("app", appName)
	slog.SetDefault(logger)
	logger.Info("Structured logging re-initialized", "level", logLevel.String())
}

func loadConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.config/" + appName)
	viper.AddConfigPath("/etc/" + appName)

	// Set defaults explicitly
	viper.SetDefault("nvdApiKey", "")
	viper.SetDefault("maxConcurrentFetches", defaultMaxConcurrentFetches)
	viper.SetDefault("requestTimeoutSec", defaultRequestTimeoutSec)
	viper.SetDefault("maxRetries", defaultMaxRetries)
	viper.SetDefault("initialBackoffSec", defaultInitialBackoffSec)
	viper.SetDefault("rateLimitRequests", defaultRateLimitRequests)
	viper.SetDefault("rateLimitPeriodSec", defaultRateLimitPeriodSec)
	viper.SetDefault("logLevel", defaultLogLevel)
	viper.SetDefault("metricPriorities", defaultMetricPriorities)

	viper.SetEnvPrefix("NVDLOOKUP")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	viper.BindEnv("nvdApiKey", "NVD_API_KEY")

	configRead := false
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Info("Config file ('config.yaml') not found. Using defaults and environment variables.") // Changed to Info
		} else {
			logger.Error("Error reading config file, proceeding with defaults/env vars", "path", viper.ConfigFileUsed(), "error", err)
		}
	} else {
		configRead = true
	}

	if err := viper.Unmarshal(&cfg); err != nil {
		logger.Error("FATAL: Unable to decode config into struct, check config file structure.", "error", err)
		os.Exit(1) // Exit if config structure is wrong
	}

	// Post-load validation/cleanup for numeric values
	if cfg.MaxConcurrentFetches <= 0 {
		cfg.MaxConcurrentFetches = defaultMaxConcurrentFetches
		logger.Warn("Invalid maxConcurrentFetches, using default", "value", defaultMaxConcurrentFetches)
	}
	if cfg.RequestTimeoutSec <= 0 {
		cfg.RequestTimeoutSec = defaultRequestTimeoutSec
		logger.Warn("Invalid requestTimeoutSec, using default", "value", defaultRequestTimeoutSec)
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = defaultMaxRetries
		logger.Warn("Invalid maxRetries, using default", "value", defaultMaxRetries)
	}
	if cfg.InitialBackoffSec <= 0 {
		cfg.InitialBackoffSec = defaultInitialBackoffSec
		logger.Warn("Invalid initialBackoffSec, using default", "value", defaultInitialBackoffSec)
	}
	if cfg.RateLimitRequests <= 0 {
		cfg.RateLimitRequests = defaultRateLimitRequests
		logger.Warn("Invalid rateLimitRequests, using default", "value", defaultRateLimitRequests)
	}
	if cfg.RateLimitPeriodSec <= 0 {
		cfg.RateLimitPeriodSec = defaultRateLimitPeriodSec
		logger.Warn("Invalid rateLimitPeriodSec, using default", "value", defaultRateLimitPeriodSec)
	}

	if configRead {
		logger.Info("Configuration loaded successfully", "source_file", viper.ConfigFileUsed())
	} else {
		logger.Info("Configuration initialized using defaults and environment variables.")
	}
	logger.Debug("Effective Configuration", "config", cfg) // Log full config at debug
}

// validateAndSortPriorities checks config and sorts priority list
func validateAndSortPriorities() {
	logger.Debug("Validating and sorting metric priorities from effective config...")
	prioritiesFromConfig := cfg.MetricPriorities // Use loaded config struct
	if len(prioritiesFromConfig) == 0 {
		logger.Error("FATAL CONFIGURATION ERROR: metricPriorities map is empty in effective config.")
		os.Exit(1) // Exit as priorities are fundamental
	}

	weightsSeen := make(map[int]string)
	tempPriorities := make([]MetricPriorityConfig, 0, len(prioritiesFromConfig))

	for version, weight := range prioritiesFromConfig {
		if !strings.HasPrefix(version, "v") {
			logger.Warn("Metric priority version might be invalid format", "version", version)
		}
		if existingVersion, found := weightsSeen[weight]; found {
			logger.Error("FATAL CONFIGURATION ERROR: Duplicate metric priority weight found", "weight", weight, "version1", existingVersion, "version2", version)
			os.Exit(1) // Exit on duplicate weights
		}
		weightsSeen[weight] = version
		tempPriorities = append(tempPriorities, MetricPriorityConfig{Version: version, Weight: weight})
	}

	sort.Slice(tempPriorities, func(i, j int) bool { return tempPriorities[i].Weight > tempPriorities[j].Weight })
	sortedPriorities = tempPriorities
	logger.Info("Metric priority order validated and set", "priorities", sortedPriorities)
}

func setupHTTPClient() {
	httpClient = &http.Client{
		Timeout: time.Duration(cfg.RequestTimeoutSec) * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: cfg.MaxConcurrentFetches * 2, // Allow more idle conns than workers
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	logger.Debug("HTTP client initialized", "timeout_seconds", cfg.RequestTimeoutSec)
}

func setUserAgent() {
	userAgent = fmt.Sprintf("%s/%s (opensecurity)", appName, appVersion)
	logger.Debug("User agent set", "user_agent", userAgent)
}

func validateCVEInput(rawIDs []string) []string {

	// --- Validate, Normalize (Lowercase), and Deduplicate ---
	validatedIDs := make([]string, 0, len(rawIDs))
	seenIDs := make(map[string]bool)
	invalidCount, duplicateCount, emptyCount := 0, 0, 0

	for _, idRaw := range rawIDs {
		idLower := strings.ToLower(strings.TrimSpace(idRaw))
		if idLower == "" {
			emptyCount++
			continue
		}
		if !cveRegex.MatchString(idLower) {
			logger.Warn("Invalid CVE ID format provided, skipping.", "cve_id_raw", idRaw)
			invalidCount++
			continue
		}
		if seenIDs[idLower] {
			duplicateCount++
			continue
		}
		validatedIDs = append(validatedIDs, idLower)
		seenIDs[idLower] = true
	}

	if emptyCount > 0 {
		logger.Warn("Skipped empty input lines/args", "count", emptyCount)
	}
	if invalidCount > 0 {
		logger.Warn("Skipped invalid CVE ID formats", "count", invalidCount)
	}
	if duplicateCount > 0 {
		logger.Info("Ignored duplicate CVE IDs", "count", duplicateCount)
	}

	if len(validatedIDs) == 0 {
		logger.Error("FATAL: No valid, unique CVE IDs found after processing input.")
		os.Exit(1)
	}
	return validatedIDs
}

// printUsageAndExit prints help message and exits
func printUsageAndExit() {
	fmt.Fprintf(os.Stderr, "\nUsage:\n")
	fmt.Fprintf(os.Stderr, "  %s <CVE-ID-1> ... [CVE-ID-%d]  (Max %d IDs via CLI)\n", os.Args[0], maxCLIInputCVEs, maxCLIInputCVEs)
	fmt.Fprintf(os.Stderr, "  %s <path/to/cves.json>       (Max %d IDs via JSON file)\n", os.Args[0], maxJSONInputCVEs)
	fmt.Fprintf(os.Stderr, "  %s -                         (Read JSON array from stdin, max %d IDs)\n", os.Args[0], maxJSONInputCVEs)
	fmt.Fprintf(os.Stderr, "  cat cves.txt | %s             (Read CVEs one per line from stdin, max %d IDs)\n", os.Args[0], maxJSONInputCVEs)
	fmt.Fprintf(os.Stderr, "\nJSON file/stdin should contain an array of CVE ID strings.\n")
	fmt.Fprintf(os.Stderr, "Requires NVD_API_KEY env var (or nvdApiKey in config.yaml).\n")
	fmt.Fprintf(os.Stderr, "See config.yaml for settings (outputMode, logging, rate limits etc.).\n")
	os.Exit(1)
}

// processResults handles results based on configured outputMode
func processResults(ctx context.Context, esClient opengovernance.Client, request tasks.TaskRequest, results <-chan CVEProcessingResult) int {
	errorCount := 0
	successfulCount := 0

	for {
		select {
		case result, ok := <-results:
			if !ok {
				logger.Info("Result processing finished.")
				return errorCount
			}

			// Process one result
			log := logger.With("cve_id", result.CVEID) // Add CVE ID for context
			if result.Error != nil {
				log.Error("Failed processing CVE", "error", result.Error)
				errorCount++
			} else if result.Output != nil {
				successfulCount++
				log.Debug("Successfully processed CVE")
				err := sendCveDetails(esClient, request, result.Output)
				if err != nil {
					log.Error("Failed to send CVE details to OSS Index", "error", err)
					errorCount++
				}
			} else {
				log.Warn("Received nil data and nil error from worker")
			}

		case <-ctx.Done():
			logger.Warn("Context cancelled while processing results. Output may be incomplete.", "error", ctx.Err())
			return errorCount + 1 // Indicate error due to cancellation
		}
	}
}

// --- Worker Goroutine ---

func worker(ctx context.Context, log *slog.Logger, id int, jobs <-chan string, results chan<- CVEProcessingResult, wg *sync.WaitGroup, apiKey string, limiter *rate.Limiter) {
	defer wg.Done()
	log.Debug("Worker started")
	for {
		select {
		case cveID, ok := <-jobs:
			if !ok {
				log.Debug("Worker finished: jobs channel closed")
				return
			}
			log := log.With("cve_id", cveID) // Add CVE ID to worker's logger context
			log.Debug("Worker processing job")
			outputCVE, err := fetchAndProcessCVE(ctx, log, cveID, apiKey, limiter) // Pass context and logger

			// Send result back, checking for context cancellation first
			select {
			case results <- CVEProcessingResult{CVEID: cveID, Output: outputCVE, Error: err}:
				// Result sent
			case <-ctx.Done():
				log.Warn("Context cancelled while sending result", "error", ctx.Err())
				return // Stop worker
			}

		case <-ctx.Done():
			log.Warn("Worker shutting down due to context cancellation", "error", ctx.Err())
			return
		}
	}
}

// --- Core Logic Functions ---

// fetchAndProcessCVE coordinates fetching, parsing, and transforming for one CVE
func fetchAndProcessCVE(ctx context.Context, log *slog.Logger, cveIDLower string, apiKey string, limiter *rate.Limiter) (*OutputCVE, error) {
	// 1. Adhere to rate limit, respecting context cancellation
	waitCtx, cancelWait := context.WithTimeout(ctx, time.Duration(cfg.RequestTimeoutSec+15)*time.Second) // Generous wait timeout
	defer cancelWait()
	log.Debug("Waiting for rate limiter...")
	if err := limiter.Wait(waitCtx); err != nil {
		log.Error("Rate limiter wait failed", "error", err)
		return nil, fmt.Errorf("rate limiter error: %w", err) // Propagate context error if applicable
	}
	log.Debug("Rate limit permission granted.")

	// Check context *after* potentially long wait but *before* network call
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 2. Fetch NVD data (use uppercase for API call), passing context and logger
	cveIDForAPI := strings.ToUpper(cveIDLower)
	bodyBytes, err := fetchNVDDataWithRetry(ctx, log, cveIDForAPI, apiKey)
	if err != nil {
		return nil, err
	} // Error already includes context

	// Check context again after fetch
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 3. Unmarshal JSON response
	var inputData InputNVDResponse
	log.Debug("Unmarshalling NVD response")
	if err := json.Unmarshal(bodyBytes, &inputData); err != nil {
		log.Error("Failed to unmarshal NVD JSON", "error", err, "body_snippet", limitString(string(bodyBytes), 200))
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}

	// 4. Validate response structure and ID
	if len(inputData.Vulnerabilities) == 0 {
		log.Warn("CVE not found in NVD response")
		return nil, fmt.Errorf("CVE %s not found in NVD response", cveIDForAPI)
	}
	inputVuln := inputData.Vulnerabilities[0]
	if len(inputData.Vulnerabilities) > 1 {
		log.Warn("API returned multiple vulnerabilities for single CVE request. Processing first.", "count", len(inputData.Vulnerabilities))
	}
	if returnedIDLower := strings.ToLower(inputVuln.CVE.ID); returnedIDLower != cveIDLower {
		log.Warn("API returned different CVE ID than requested.", "requested_lower", cveIDLower, "returned_actual", inputVuln.CVE.ID)
		// Decide if this is an error or just a warning. For now, proceed.
	}

	// 5. Transform data into desired output format
	log.Debug("Transforming vulnerability data")
	outputCVE := transformSingleVulnerability(log, inputVuln) // Pass logger
	log.Debug("Transformation complete")
	return &outputCVE, nil
}

// fetchNVDDataWithRetry handles HTTP GET request with backoff, respecting context
func fetchNVDDataWithRetry(ctx context.Context, log *slog.Logger, cveIDForAPI, apiKey string) ([]byte, error) {
	apiURL := fmt.Sprintf("%s?cveId=%s", nvdBaseURL, cveIDForAPI)
	var lastErr error

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		// Check context before attempting/retrying
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if attempt > 0 {
			backoffDuration := time.Duration(cfg.InitialBackoffSec) * time.Second * time.Duration(math.Pow(2, float64(attempt-1)))
			log.Warn("Retrying request after error", "attempt", attempt, "max_retries", cfg.MaxRetries, "wait_duration", backoffDuration, "last_error", lastErr)
			// Sleep respecting context cancellation
			select {
			case <-time.After(backoffDuration): // Wait for backoff duration
			case <-ctx.Done(): // If context cancelled during sleep
				log.Warn("Context cancelled during backoff sleep", "error", ctx.Err())
				return nil, ctx.Err()
			}
		}

		// Create request with context for this attempt
		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create request error (attempt %d): %w", attempt, err)
		} // Should be rare

		req.Header.Add("apiKey", apiKey)
		req.Header.Add("User-Agent", userAgent)

		log.Info("Requesting NVD API", "attempt", attempt+1)
		resp, err := httpClient.Do(req) // Use shared client

		// --- Handle Network/Transport/Context Errors ---
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				log.Warn("Context cancelled/timed out during HTTP request", "error", err)
				return nil, err // Propagate context error
			}
			lastErr = fmt.Errorf("request execution error (attempt %d): %w", attempt, err)
			log.Warn("HTTP request execution failed, will retry if possible", "error", err)
			continue // Retry on potentially transient network errors
		}

		// --- Handle HTTP Response ---
		bodyBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("read body error (attempt %d, status %d): %w", attempt, resp.StatusCode, readErr)
			log.Warn("Failed to read response body, will retry if possible", "status", resp.StatusCode, "error", readErr)
			continue // Retry on read errors
		}

		// --- Handle HTTP Status Codes ---
		statusCode := resp.StatusCode
		log := log.With(slog.Int("status_code", statusCode)) // Add status code to context
		switch {
		case statusCode == http.StatusOK:
			log.Info("Successfully fetched data from NVD")
			return bodyBytes, nil // Success!

		case statusCode == http.StatusTooManyRequests || statusCode == http.StatusForbidden: // 429 or 403
			lastErr = fmt.Errorf("retryable NVD API error (%d)", statusCode)
			log.Warn("NVD API returned retryable status, will backoff and retry", "error", lastErr)
			// Continue loop for backoff/retry

		case statusCode >= 500: // 5xx Server Errors
			lastErr = fmt.Errorf("NVD server error (%d)", statusCode)
			log.Warn("NVD API returned server error, will backoff and retry", "error", lastErr)
			// Continue loop for backoff/retry

		default: // Other 4xx Client Errors (e.g., 404 Not Found, 400 Bad Request)
			lastErr = fmt.Errorf("non-retryable NVD client error (%d)", statusCode)
			if len(bodyBytes) > 0 {
				lastErr = fmt.Errorf("%w - Body: %s", lastErr, limitString(string(bodyBytes), 200))
			}
			log.Error("Received non-retryable client error from NVD", "error", lastErr)
			// Do NOT retry other client errors - return the error immediately
			return nil, lastErr
		}
		// Loop continues for retryable errors
	}

	// If the loop finishes, all retries have been exhausted
	log.Error("Request failed after maximum retries", "max_retries", cfg.MaxRetries, "last_error", lastErr)
	return nil, fmt.Errorf("retries exceeded after %d attempts: %w", cfg.MaxRetries, lastErr)
}

// transformSingleVulnerability applies filtering and prioritization rules
func transformSingleVulnerability(log *slog.Logger, vuln InputVulnerability) OutputCVE {
	log.Debug("Starting transformation")
	outputCVE := OutputCVE{
		CveID:                 vuln.CVE.ID,
		SourceIdentifier:      vuln.CVE.SourceIdentifier,
		Published:             vuln.CVE.Published,
		LastModified:          vuln.CVE.LastModified,
		VulnStatus:            vuln.CVE.VulnStatus,
		Descriptions:          make([]OutputDescription, 0, 1),
		Metrics:               OutputMetrics{}, // Initialize empty
		Weaknesses:            make([]OutputWeakness, 0, len(vuln.CVE.Weaknesses)),
		CisaExploitAdd:        vuln.CVE.CisaExploitAdd,
		CisaActionDue:         vuln.CVE.CisaActionDue,
		CisaRequiredAction:    vuln.CVE.CisaRequiredAction,
		CisaVulnerabilityName: vuln.CVE.CisaVulnerabilityName,
	}

	// Filter descriptions for English ('en')
	foundDesc := false
	for _, desc := range vuln.CVE.Descriptions {
		if desc.Lang == "en" {
			outputCVE.Descriptions = append(outputCVE.Descriptions, OutputDescription{Lang: desc.Lang, Value: desc.Value})
			foundDesc = true
			break
		}
	}
	if !foundDesc {
		log.Debug("No English description found")
	}

	// Apply Metrics Priority and populate normalized fields
	foundMetrics := false
	for _, priorityConfig := range sortedPriorities { // Use sorted global priorities
		version := priorityConfig.Version
		metricsPopulated := false

		switch version {
		case "v4.0":
			if len(vuln.CVE.Metrics.CvssMetricV40) > 0 {
				outputCVE.Metrics.CvssMetricV40 = vuln.CVE.Metrics.CvssMetricV40
				metricsPopulated = true
			}
		case "v3.1":
			if !foundMetrics && len(vuln.CVE.Metrics.CvssMetricV31) > 0 {
				outputCVE.Metrics.CvssMetricV31 = vuln.CVE.Metrics.CvssMetricV31
				metricsPopulated = true
			}
		case "v2.0":
			if !foundMetrics && len(vuln.CVE.Metrics.CvssMetricV2) > 0 {
				outputCVE.Metrics.CvssMetricV2 = vuln.CVE.Metrics.CvssMetricV2
				metricsPopulated = true
			}
		}

		if metricsPopulated {
			foundMetrics = true
			// Populate normalized fields based on the version found
			populateNormalizedCVSS(log, &outputCVE, version, &vuln.CVE.Metrics) // Pass logger
			log.Debug("Applied highest priority metrics", "version", version)
			break // Strict priority
		}
	}
	if !foundMetrics {
		log.Debug("No prioritized metrics found")
	}

	// Filter weaknesses descriptions for English ('en')
	for _, weak := range vuln.CVE.Weaknesses {
		filteredWeaknessDesc := make([]OutputDescription, 0)
		for _, desc := range weak.Description {
			if desc.Lang == "en" {
				filteredWeaknessDesc = append(filteredWeaknessDesc, OutputDescription{Lang: desc.Lang, Value: desc.Value})
			}
		}
		if len(filteredWeaknessDesc) > 0 {
			outputCVE.Weaknesses = append(outputCVE.Weaknesses, OutputWeakness{
				Source: weak.Source, Type: weak.Type, Description: filteredWeaknessDesc,
			})
		} else {
			log.Debug("Weakness source skipped due to no English description", "source", weak.Source)
		}
	}

	log.Debug("Transformation finished")
	return outputCVE
}

// populateNormalizedCVSS fills the top-level CVSS fields based on the prioritized metric data found
// It modifies the outputCVE struct directly via the pointer.
func populateNormalizedCVSS(log *slog.Logger, outputCVE *OutputCVE, version string, metrics *InputMetrics) {
	outputCVE.CvssVersion = version // Always set the version that was chosen

	// Use data from the first metric entry of the chosen version for normalization
	log = log.With("cvss_version_chosen", version) // Add chosen version to logger context
	switch version {
	case "v4.0":
		if len(metrics.CvssMetricV40) > 0 {
			// Use first available metric for normalized fields
			m := metrics.CvssMetricV40[0].CvssData // Get V4 data
			log.Debug("Populating normalized fields from CVSS v4.0")
			outputCVE.CvssScore = m.BaseScore
			outputCVE.CvssSeverity = m.BaseSeverity
			outputCVE.CvssAttackVector = m.AttackVector
			outputCVE.CvssAttackComplexity = m.AttackComplexity
			outputCVE.CvssPrivilegesRequired = m.PrivilegesRequired
			outputCVE.CvssUserInteraction = m.UserInteraction
			outputCVE.CvssConfImpact = m.VulnConfidentialityImpact // Use Vuln... fields for v4 base impact
			outputCVE.CvssIntegImpact = m.VulnIntegrityImpact
			outputCVE.CvssAvailImpact = m.VulnAvailabilityImpact
		} else {
			// This should ideally not happen if called correctly after checking len > 0, but log defensively
			log.Warn("Attempted to populate normalized fields from v4.0, but metric list was empty")
		}
	case "v3.1":
		if len(metrics.CvssMetricV31) > 0 {
			m := metrics.CvssMetricV31[0].CvssData // Get V3.1 data
			log.Debug("Populating normalized fields from CVSS v3.1")
			outputCVE.CvssScore = m.BaseScore
			outputCVE.CvssSeverity = m.BaseSeverity
			outputCVE.CvssAttackVector = m.AttackVector
			outputCVE.CvssAttackComplexity = m.AttackComplexity
			outputCVE.CvssPrivilegesRequired = m.PrivilegesRequired
			outputCVE.CvssUserInteraction = m.UserInteraction
			outputCVE.CvssConfImpact = m.ConfidentialityImpact
			outputCVE.CvssIntegImpact = m.IntegrityImpact
			outputCVE.CvssAvailImpact = m.AvailabilityImpact
		} else {
			log.Warn("Attempted to populate normalized fields from v3.1, but metric list was empty")
		}
	case "v2.0":
		if len(metrics.CvssMetricV2) > 0 {
			m := metrics.CvssMetricV2[0] // Get V2 metric struct
			mData := m.CvssData          // Get V2 data struct
			log.Debug("Populating normalized fields from CVSS v2.0")
			outputCVE.CvssScore = mData.BaseScore
			outputCVE.CvssSeverity = m.BaseSeverity                 // Severity is on metric struct for v2
			outputCVE.CvssAttackVector = mData.AccessVector         // Map v2 name
			outputCVE.CvssAttackComplexity = mData.AccessComplexity // Map v2 name
			// Map v2 Authentication -> Privileges Required
			switch mData.Authentication {
			case "NONE":
				outputCVE.CvssPrivilegesRequired = "NONE"
			case "SINGLE_INSTANCE", "SINGLE":
				outputCVE.CvssPrivilegesRequired = "LOW"
			case "MULTIPLE_INSTANCES", "MULTIPLE":
				outputCVE.CvssPrivilegesRequired = "HIGH"
			default:
				outputCVE.CvssPrivilegesRequired = strings.ToUpper(mData.Authentication) // Fallback or UNKNOWN?
				log.Warn("Unknown CVSSv2 Authentication mapping", "v2_auth", mData.Authentication)
			}
			// Map v2 User Interaction Required -> User Interaction
			if m.UserInteractionRequired {
				outputCVE.CvssUserInteraction = "REQUIRED"
			} else {
				outputCVE.CvssUserInteraction = "NONE"
			}
			// Map v2 Impact -> v3/v4 Impact levels (using a map for clarity)
			impactMap := map[string]string{"NONE": "NONE", "PARTIAL": "LOW", "COMPLETE": "HIGH"}
			outputCVE.CvssConfImpact = impactMap[mData.ConfidentialityImpact]
			outputCVE.CvssIntegImpact = impactMap[mData.IntegrityImpact]
			outputCVE.CvssAvailImpact = impactMap[mData.AvailabilityImpact]
		} else {
			log.Warn("Attempted to populate normalized fields from v2.0, but metric list was empty")
		}
	default:
		// Should not happen if called correctly based on sortedPriorities check
		log.Warn("Unknown CVSS version encountered in populateNormalizedCVSS", "version", version)
	}
	// No return value needed as outputCVE is modified via pointer
}

// limitString truncates a string for cleaner logging
func limitString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// GetVulnerabilitiesFromQueryID fetches SBOMs using a named query ID. Reads QueryLimit from params.
func GetVulnerabilitiesFromQueryID(ctx context.Context, coreServiceClient coreClient.CoreServiceClient, params map[string]any) ([]string, error) {
	queryLimit := getIntParam(params, "query_limit", 1000)
	queryParams := make(map[string]string)
	if v, ok := params["query_params"]; ok {
		if qp, ok := v.(map[string]interface{}); ok {
			for k, val := range qp {
				if vs, ok := val.(string); ok {
					queryParams[k] = vs
				}
			}
		}
	}
	queryID, ok := params["query_id"].(string)
	if !ok || queryID == "" {
		return nil, fmt.Errorf("query id parameter ('query_id') is missing or not a string")
	}
	logger := zap.L().With(zap.String("query_id", queryID), zap.Int("limit", queryLimit))
	logger.Info("Fetching SBOMs via named query")

	// Corrected Call: Pass httpclient.Context with UserRole and Ctx (trying 'Ctx'), and request struct by value.
	queryResponse, err := coreServiceClient.RunQueryByID(&httpclient.Context{
		UserRole: authApi.AdminRole, // Include UserRole from original code
		Ctx:      ctx,               // Trying 'Ctx' as the field name for the context
	}, coreApi.RunQueryByIDRequest{ // Pass request struct by value
		ID:          queryID,
		Type:        "named_query",
		QueryParams: queryParams,
		Page:        coreApi.Page{No: 1, Size: queryLimit},
	})

	if err != nil {
		if ctx.Err() != nil { // Check specifically for context cancellation
			logger.Error("Core service query cancelled", zap.Error(ctx.Err()))
			return nil, ctx.Err()
		}
		logger.Error("Core service query by ID failed", zap.Error(err))
		return nil, fmt.Errorf("running core service query by id %s failed: %w", queryID, err)
	}
	logger.Info("Received response from core service query", zap.Int("result_count", len(queryResponse.Result)))
	return mapCoreQueryResultToCve(queryResponse)
}

// GetVulnerabilitiesFromInlineQuery fetches SBOMs using an inline query string. Reads QueryLimit from params.
func GetVulnerabilitiesFromInlineQuery(ctx context.Context, coreServiceClient coreClient.CoreServiceClient, params map[string]any) ([]string, error) {
	queryLimit := getIntParam(params, "query_limit", 1000)
	queryToExecute, ok := params["query_to_execute"].(string)
	if !ok || queryToExecute == "" {
		return nil, fmt.Errorf("query to execute parameter ('query_to_execute') is missing or not a string")
	}
	logger := zap.L().With(zap.Int("limit", queryLimit))
	logger.Info("Fetching SBOMs via inline query")

	// Corrected Call: Using httpclient.Context with UserRole from authApi package and Ctx field
	queryResponse, err := coreServiceClient.RunQuery(&httpclient.Context{
		UserRole: authApi.AdminRole, // Uses the imported authApi alias
		Ctx:      ctx,
	}, coreApi.RunQueryRequest{ // Pass request struct by value
		Query: &queryToExecute,
		Page:  coreApi.Page{No: 1, Size: queryLimit},
	})

	if err != nil {
		if ctx.Err() != nil {
			logger.Error("Core service inline query cancelled", zap.Error(ctx.Err()))
			return nil, ctx.Err()
		}
		logger.Error("Core service inline query failed", zap.Error(err))
		return nil, fmt.Errorf("running core service inline query failed: %w", err)
	}
	logger.Info("Received response from core service query", zap.Int("result_count", len(queryResponse.Result)))
	return mapCoreQueryResultToCve(queryResponse)
}
func mapCoreQueryResultToCve(queryResponse *coreApi.RunQueryResponse) ([]string, error) {
	var ids []string
	headerMap := make(map[string]int)
	for i, h := range queryResponse.Headers {
		headerMap[h] = i
	}
	idx, ok1 := headerMap["cve_id"]
	if !ok1 {
		return nil, fmt.Errorf("core service query result missing required columns (need: cve_id), found: %v", queryResponse.Headers)
	}
	for i, r := range queryResponse.Result {
		if val, ok := r[idx].(string); ok {
			if val == "" {
				continue
			}
			ids = append(ids, val)
		} else {
			zap.L().Warn("Unexpected type/nil for package_name", zap.Int("row", i))
		}
	}
	return ids, nil
}

func sendCveDetails(esClient og_es_sdk.Client, request tasks.TaskRequest, r *OutputCVE) (err error) {
	if r == nil {
		return nil
	}
	esResult := &es.TaskResult{
		PlatformID:   fmt.Sprintf("%s:::%s:::%s", request.TaskDefinition.TaskType, request.TaskDefinition.ResultType, r.UniqueID()),
		ResourceID:   r.UniqueID(),
		ResourceName: r.CveID,
		Description:  r, // Embed the full SbomVulnerabilities struct
		ResultType:   strings.ToLower(request.TaskDefinition.ResultType),
		TaskType:     request.TaskDefinition.TaskType,
		Metadata:     nil, // Consider adding params map here? request.TaskDefinition.Params,
		DescribedAt:  time.Now().Unix(),
		DescribedBy:  strconv.FormatUint(uint64(request.TaskDefinition.RunID), 10),
	}
	keys, _ := esResult.KeysAndIndex()
	esResult.EsID = es.HashOf(keys...)
	esResult.EsIndex = "cve_details"

	// This calls the function assumed to be in another file with the 2-arg signature
	err = sendDataToOpensearch(esClient.ES(), esResult, "cve_details")
	if err != nil {
		return fmt.Errorf("sending final result to opensearch: %w", err)
	}

	return nil
}

func getIntParam(params map[string]any, key string, defaultValue int) int {
	if v, ok := params[key]; ok {
		if vv, ok := v.(float64); ok {
			return int(vv)
		}
		if vv, ok := v.(int); ok {
			return vv
		}
		if vv, ok := v.(string); ok {
			if i, err := strconv.Atoi(vv); err == nil {
				return i
			}
		}
	}
	return defaultValue
}

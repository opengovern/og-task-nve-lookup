package task

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/opengovern/og-task-nve-lookup/envs"
	authApi "github.com/opengovern/og-util/pkg/api"
	"github.com/opengovern/og-util/pkg/es"
	"github.com/opengovern/og-util/pkg/httpclient"
	"github.com/opengovern/og-util/pkg/jq"
	"github.com/opengovern/og-util/pkg/opengovernance-es-sdk"
	og_es_sdk "github.com/opengovern/og-util/pkg/opengovernance-es-sdk"
	"github.com/opengovern/og-util/pkg/tasks"
	coreApi "github.com/opengovern/opensecurity/services/core/api"
	coreClient "github.com/opengovern/opensecurity/services/core/client"
	"github.com/opengovern/opensecurity/services/tasks/db/models"
	"github.com/opengovern/opensecurity/services/tasks/scheduler"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"io"
	"log"
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
	appName          = "nvd_transformer"
	appVersion       = "3.2" // Version reflecting uppercase log fix
	nvdBaseURL       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	maxCLIInputCVEs  = 5
	maxFileInputCVEs = 1000
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

var cveRegex = regexp.MustCompile(`^cve-\d{4}-\d{4,}$`)

type Config struct {
	NvdApiKey            string  `mapstructure:"nvdApiKey"`
	LogLevel             string  `mapstructure:"logLevel"`
	MaxConcurrentFetches int     `mapstructure:"maxConcurrentFetches"`
	RequestTimeoutSec    int     `mapstructure:"requestTimeoutSec"`
	MaxRetries           int     `mapstructure:"maxRetries"`
	InitialBackoffSec    int     `mapstructure:"initialBackoffSec"`
	RateLimitRequests    float64 `mapstructure:"rateLimitRequests"`
	RateLimitPeriodSec   int     `mapstructure:"rateLimitPeriodSec"`
}

var (
	cfg        Config
	httpClient *http.Client
	userAgent  string
)

// --- Input Struct Definitions (NVD API Format - camelCase) ---
// --- Unchanged ---
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
	Metrics               *InputMetrics      `json:"metrics"`
	Weaknesses            []InputWeakness    `json:"weaknesses"`
	CisaExploitAdd        *string            `json:"cisaExploitAdd"`
	CisaActionDue         *string            `json:"cisaActionDue"`
	CisaRequiredAction    *string            `json:"cisaRequiredAction"`
	CisaVulnerabilityName *string            `json:"cisaVulnerabilityName"`
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
	Version                   string  `json:"version"`
	VectorString              string  `json:"vectorString"`
	BaseScore                 float64 `json:"baseScore"`
	BaseSeverity              string  `json:"baseSeverity"`
	AttackVector              string  `json:"attackVector"`
	AttackComplexity          string  `json:"attackComplexity"`
	AttackRequirements        string  `json:"attackRequirements"`
	PrivilegesRequired        string  `json:"privilegesRequired"`
	UserInteraction           string  `json:"userInteraction"`
	VulnConfidentialityImpact string  `json:"vulnConfidentialityImpact"`
	VulnIntegrityImpact       string  `json:"vulnIntegrityImpact"`
	VulnAvailabilityImpact    string  `json:"vulnAvailabilityImpact"`
	SubConfidentialityImpact  string  `json:"subConfidentialityImpact"`
	SubIntegrityImpact        string  `json:"subIntegrityImpact"`
	SubAvailabilityImpact     string  `json:"subAvailabilityImpact"`
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

type TargetCvssMetricV2 struct {
	Source                  string           `json:"source"`
	Type                    string           `json:"type"`
	CvssData                TargetCvssDataV2 `json:"cvss_data"`
	ExploitabilityScore     float64          `json:"exploitability_score"`
	ImpactScore             float64          `json:"impact_score"`
	AcInsufInfo             bool             `json:"ac_insuf_info"`
	ObtainAllPrivilege      bool             `json:"obtain_all_privilege"`
	ObtainUserPrivilege     bool             `json:"obtain_user_privilege"`
	ObtainOtherPrivilege    bool             `json:"obtain_other_privilege"`
	UserInteractionRequired bool             `json:"user_interaction_required"`
}
type TargetCvssDataV2 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vector_string"`
	AccessVector          string  `json:"access_vector"`
	AccessComplexity      string  `json:"access_complexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentiality_impact"`
	IntegrityImpact       string  `json:"integrity_impact"`
	AvailabilityImpact    string  `json:"availability_impact"`
	BaseScore             float64 `json:"base_score"`
	BaseSeverity          string  `json:"base_severity"` // Moved inside
}
type TargetCvssMetricV31 struct {
	Source              string            `json:"source"`
	Type                string            `json:"type"`
	CvssData            TargetCvssDataV31 `json:"cvss_data"`
	ExploitabilityScore float64           `json:"exploitability_score"`
	ImpactScore         float64           `json:"impact_score"`
}
type TargetCvssDataV31 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vector_string"`
	AttackVector          string  `json:"attack_vector"`
	AttackComplexity      string  `json:"attack_complexity"`
	PrivilegesRequired    string  `json:"privileges_required"`
	UserInteraction       string  `json:"user_interaction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentiality_impact"`
	IntegrityImpact       string  `json:"integrity_impact"`
	AvailabilityImpact    string  `json:"availability_impact"`
	BaseScore             float64 `json:"base_score"`
	BaseSeverity          string  `json:"base_severity"`
}
type TargetCvssMetricV40 struct {
	Source   string            `json:"source"`
	Type     string            `json:"type"`
	CvssData TargetCvssDataV40 `json:"cvss_data"`
}
type TargetCvssDataV40 struct {
	Version                   string  `json:"version"`
	VectorString              string  `json:"vector_string"`
	BaseScore                 float64 `json:"base_score"`
	BaseSeverity              string  `json:"base_severity"`
	AttackVector              string  `json:"attack_vector"`
	AttackComplexity          string  `json:"attack_complexity"`
	AttackRequirements        string  `json:"attack_requirements"`
	PrivilegesRequired        string  `json:"privileges_required"`
	UserInteraction           string  `json:"user_interaction"`
	VulnConfidentialityImpact string  `json:"vuln_confidentiality_impact"`
	VulnIntegrityImpact       string  `json:"vuln_integrity_impact"`
	VulnAvailabilityImpact    string  `json:"vuln_availability_impact"`
	SubConfidentialityImpact  string  `json:"sub_confidentiality_impact"`
	SubIntegrityImpact        string  `json:"sub_integrity_impact"`
	SubAvailabilityImpact     string  `json:"sub_availability_impact"`
}
type TargetWeakness struct {
	Source      string             `json:"source"`
	Type        string             `json:"type"`
	Description []InputDescription `json:"description"` // Re-use InputDescription
}

// --- Result struct for worker communication (Unchanged) ---
type CVEProcessingResult struct {
	InputCVEID string // The original requested ID (lowercase)
	Output     *TargetCve
	Error      error
}

// --- Initialization (Unchanged) ---
func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds) // Added microseconds
	loadConfig()
	setupHTTPClient()
	setUserAgent()
}

func RunTask(ctx context.Context, jq *jq.JobQueue, coreServiceEndpoint string, esClient opengovernance.Client, _ *zap.Logger, request tasks.TaskRequest, response *scheduler.TaskResponse) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var rawCveIDs []string
	var err error

	log.Printf("Fetching SBOMs for task")
	inventoryClient := coreClient.NewCoreServiceClient(coreServiceEndpoint)

	if queryID, ok := request.TaskDefinition.Params["query_id"].(string); ok && queryID != "" {
		rawCveIDs, err = WithRetry(func() ([]string, error) {
			return GetVulnerabilitiesFromQueryID(ctx, inventoryClient, request.TaskDefinition.Params)
		})
	} else if queryExec, ok := request.TaskDefinition.Params["query_to_execute"].(string); ok && queryExec != "" {
		rawCveIDs, err = WithRetry(func() ([]string, error) {
			return GetVulnerabilitiesFromInlineQuery(ctx, inventoryClient, request.TaskDefinition.Params)
		})
	} else {
		err = fmt.Errorf("SBOM source query not provided (missing 'query_id' or 'query_to_execute' in params)")
	}
	if err != nil {
		log.Printf("Error fetching SBOMs for task: %v", err)
		return err
	}

	var apiKey string
	log.Printf("INFO: %s starting (version %s)", appName, appVersion)
	if apiKeyTmp, ok := request.TaskDefinition.Params["nve_api_key"].(string); ok && apiKeyTmp != "" {
		apiKey = apiKeyTmp
	} else {
		log.Println("ERROR: No API Key defined")
		return fmt.Errorf("ERROR: No API Key defined")
	}

	if err = checkNvdApiKeyHealth(ctx, apiKey, httpClient, time.Duration(cfg.RequestTimeoutSec)*time.Second); err != nil {
		tmp := models.TaskSecretHealthStatusUnhealthy
		response.CredentialsHealthStatus = &tmp
		responseJson, err := json.Marshal(response)
		if err != nil {
			log.Printf("failed to create response json: %v", zap.Error(err))
			return err
		}

		if _, err = jq.Produce(ctx, envs.ResultTopicName, responseJson, fmt.Sprintf("task-run-inprogress-%d", request.TaskDefinition.RunID)); err != nil {
			log.Printf("failed to publish job in progress", zap.String("response", string(responseJson)), zap.Error(err))
		}
		return err
	} else {
		tmp := models.TaskSecretHealthStatusHealthy
		response.CredentialsHealthStatus = &tmp
		responseJson, err := json.Marshal(response)
		if err != nil {
			log.Printf("failed to create response json: %v", zap.Error(err))
			return err
		}

		if _, err = jq.Produce(ctx, envs.ResultTopicName, responseJson, fmt.Sprintf("task-run-inprogress-%d", request.TaskDefinition.RunID)); err != nil {
			log.Printf("failed to publish job in progress", zap.String("response", string(responseJson)), zap.Error(err))
		}
	}

	cveIDs := getAndValidateCVEInput(rawCveIDs)
	if len(cveIDs) == 0 {
		log.Println("INFO: No valid CVE IDs to process. Exiting.")
		return nil
	}
	log.Printf("INFO: Processing %d validated CVE IDs", len(cveIDs))
	limit := rate.Limit(cfg.RateLimitRequests / float64(cfg.RateLimitPeriodSec))
	limiter := rate.NewLimiter(limit, cfg.MaxConcurrentFetches)
	log.Printf("INFO: NVD rate limiter configured (rate: %.2f/sec, burst: %d)", float64(limit), cfg.MaxConcurrentFetches)
	jobs := make(chan string, len(cveIDs))
	results := make(chan CVEProcessingResult, len(cveIDs))
	var wg sync.WaitGroup
	log.Printf("INFO: Starting %d worker goroutines", cfg.MaxConcurrentFetches)
	for w := 1; w <= cfg.MaxConcurrentFetches; w++ {
		wg.Add(1)
		go worker(ctx, w, jobs, results, &wg, apiKey, limiter)
	}
	go func() {
		defer close(jobs)
		log.Println("DEBUG: Starting job submission")
		for _, cveID := range cveIDs {
			select {
			case jobs <- cveID:
			case <-ctx.Done():
				log.Printf("WARN: Context cancelled during job submission: %v", ctx.Err())
				return
			}
		}
		log.Println("DEBUG: Finished job submission")
	}()
	go func() {
		log.Println("DEBUG: Waiting for workers to finish...")
		wg.Wait()
		log.Println("DEBUG: All workers finished, closing results channel.")
		close(results)
	}()
	processedResults := processResults(esClient, request, ctx, results)
	errorCount := 0
	for _, res := range processedResults {
		if res.Error != nil {
			errorCount++
		}
	}
	log.Printf("INFO: Processing complete (Successful: %d, Failed: %d)", len(processedResults)-errorCount, errorCount)
	if errorCount > 0 {
		log.Println("ERROR: Completed with errors.")
		os.Exit(1)
	}
	log.Println("INFO: Completed successfully.")
	return nil
}

// --- Configuration Loading (Unchanged) ---
func loadConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.config/" + appName)
	viper.AddConfigPath("/etc/" + appName)
	viper.SetDefault("nvdApiKey", "")
	viper.SetDefault("logLevel", defaultLogLevel)
	viper.SetDefault("maxConcurrentFetches", defaultMaxConcurrentFetches)
	viper.SetDefault("requestTimeoutSec", defaultRequestTimeoutSec)
	viper.SetDefault("maxRetries", defaultMaxRetries)
	viper.SetDefault("initialBackoffSec", defaultInitialBackoffSec)
	viper.SetDefault("rateLimitRequests", defaultRateLimitRequests)
	viper.SetDefault("rateLimitPeriodSec", defaultRateLimitPeriodSec)
	viper.SetEnvPrefix("NVDLOOKUP")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	viper.BindEnv("nvdApiKey", "NVD_API_KEY")
	configRead := false
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("INFO: Config file ('config.yaml') not found.")
		} else {
			log.Printf("WARN: Error reading config file (%s): %v", viper.ConfigFileUsed(), err)
		}
	} else {
		configRead = true
	}
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("FATAL: Unable to decode config: %v", err)
	}
	if cfg.MaxConcurrentFetches <= 0 {
		cfg.MaxConcurrentFetches = defaultMaxConcurrentFetches
	}
	if cfg.RequestTimeoutSec <= 0 {
		cfg.RequestTimeoutSec = defaultRequestTimeoutSec
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.InitialBackoffSec <= 0 {
		cfg.InitialBackoffSec = defaultInitialBackoffSec
	}
	if cfg.RateLimitRequests <= 0 {
		cfg.RateLimitRequests = defaultRateLimitRequests
	}
	if cfg.RateLimitPeriodSec <= 0 {
		cfg.RateLimitPeriodSec = defaultRateLimitPeriodSec
	}
	if configRead {
		log.Printf("INFO: Config loaded from %s", viper.ConfigFileUsed())
	} else {
		log.Println("INFO: Config initialized using defaults/env.")
	}
	log.Printf("DEBUG: Effective Config: %+v", cfg)
}

// --- HTTP Client Setup (Unchanged) ---
func setupHTTPClient() {
	httpClient = &http.Client{Timeout: time.Duration(cfg.RequestTimeoutSec) * time.Second, Transport: &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: cfg.MaxConcurrentFetches * 2, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second}}
	log.Printf("DEBUG: HTTP client initialized (Timeout: %ds)", cfg.RequestTimeoutSec)
}

// --- User Agent Setup (Unchanged) ---
func setUserAgent() {
	userAgent = fmt.Sprintf("%s/%s (contact: your-email@example.com)", appName, appVersion)
	log.Printf("DEBUG: User agent set: %s", userAgent)
}

func getAndValidateCVEInput(rawIDs []string) []string {
	validatedIDs := make([]string, 0, len(rawIDs))
	seenIDs := make(map[string]bool)
	invalidCount, duplicateCount := 0, 0
	for _, idRaw := range rawIDs {
		idLower := strings.ToLower(strings.TrimSpace(idRaw))
		if idLower == "" {
			continue
		}
		if !cveRegex.MatchString(idLower) {
			log.Printf("WARN: Invalid CVE ID format skipped: %q", idRaw)
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
	if invalidCount > 0 {
		log.Printf("WARN: Skipped %d invalid CVE IDs", invalidCount)
	}
	if duplicateCount > 0 {
		log.Printf("INFO: Ignored %d duplicate CVE IDs", duplicateCount)
	}
	if len(validatedIDs) == 0 {
		log.Fatal("FATAL: No valid, unique CVE IDs found.")
	}
	return validatedIDs
}

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

// --- Result Processing (MODIFIED LOGGING) ---
func processResults(esClient opengovernance.Client, request tasks.TaskRequest, ctx context.Context, results <-chan CVEProcessingResult) []CVEProcessingResult {
	processedResults := make([]CVEProcessingResult, 0)
	log.Println("INFO: Waiting to process results...")
	for {
		select {
		case result, ok := <-results:
			if !ok {
				log.Println("INFO: Result processing finished.")
				sort.Slice(processedResults, func(i, j int) bool { return processedResults[i].InputCVEID < processedResults[j].InputCVEID })
				return processedResults
			}
			if result.Error != nil {
				log.Printf("WARN: Failed to send result for %s: %v", result.InputCVEID, result.Error)
			} else if result.Output != nil {
				err := sendCveDetails(esClient, request, result.Output)
				if err != nil {
					log.Printf("ERROR: Failed to send result for %s: %v", result.InputCVEID, err)
				}
			}
		case <-ctx.Done():
			log.Printf("WARN: Context cancelled while processing results. Output may be incomplete: %v", ctx.Err())
			sort.Slice(processedResults, func(i, j int) bool { return processedResults[i].InputCVEID < processedResults[j].InputCVEID })
			return processedResults
		}
	}
}

// --- Worker and Fetching Logic (MODIFIED LOGGING) ---
func worker(ctx context.Context, id int, jobs <-chan string, results chan<- CVEProcessingResult, wg *sync.WaitGroup, apiKey string, limiter *rate.Limiter) {
	defer wg.Done()
	log.Printf("DEBUG: Worker %d started", id)
	for {
		select {
		case cveIDLower, ok := <-jobs:
			if !ok {
				log.Printf("DEBUG: Worker %d finished: jobs channel closed", id)
				return
			}
			// MODIFIED: Create uppercase version for logging *within worker*
			cveIDUpper := strings.ToUpper(cveIDLower)
			log.Printf("DEBUG: Worker %d processing job: %s", id, cveIDUpper)
			outputCVE, err := fetchAndTransformCVE(ctx, cveIDLower, apiKey, limiter) // Pass lowercase for internal use, uppercase used inside fetchAndTransformCVE for its logging
			select {
			case results <- CVEProcessingResult{InputCVEID: cveIDLower, Output: outputCVE, Error: err}:
			case <-ctx.Done():
				log.Printf("WARN: Worker %d: Context cancelled sending result for %s: %v", id, cveIDUpper, ctx.Err())
				return // Log with uppercase
			}
		case <-ctx.Done():
			log.Printf("WARN: Worker %d shutting down due to context cancellation: %v", id, ctx.Err())
			return
		}
	}
}

func fetchAndTransformCVE(ctx context.Context, cveIDLower string, apiKey string, limiter *rate.Limiter) (*TargetCve, error) {
	// MODIFIED: Create uppercase version early for consistent logging prefix
	cveIDUpper := strings.ToUpper(cveIDLower)
	waitCtx, cancelWait := context.WithTimeout(ctx, time.Duration(cfg.RequestTimeoutSec+15)*time.Second)
	defer cancelWait()
	log.Printf("DEBUG: [%s] Waiting for rate limiter...", cveIDUpper) // Use Upper
	if err := limiter.Wait(waitCtx); err != nil {
		log.Printf("ERROR: [%s] Rate limiter wait failed: %v", cveIDUpper, err) // Use Upper
		return nil, fmt.Errorf("[%s] rate limiter error: %w", cveIDUpper, err)  // Use Upper in error
	}
	log.Printf("DEBUG: [%s] Rate limit permission granted.", cveIDUpper) // Use Upper
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Pass uppercase ID as BOTH logPrefix and cveIDForAPI to fetchNVDDataWithRetry
	bodyBytes, err := fetchNVDDataWithRetry(ctx, cveIDUpper, cveIDUpper, apiKey)
	if err != nil {
		return nil, err
	} // Errors from fetch already include the uppercase prefix
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var inputData InputNVDResponse
	log.Printf("DEBUG: [%s] Unmarshalling NVD response", cveIDUpper) // Use Upper
	if err := json.Unmarshal(bodyBytes, &inputData); err != nil {
		log.Printf("ERROR: [%s] Failed to unmarshal NVD JSON: %v", cveIDUpper, err) // Use Upper
		return nil, fmt.Errorf("[%s] unmarshal error: %w", cveIDUpper, err)         // Use Upper in error
	}

	if len(inputData.Vulnerabilities) == 0 {
		log.Printf("WARN: [%s] CVE not found in NVD response", cveIDUpper)   // Use Upper
		return nil, fmt.Errorf("[%s] not found in NVD response", cveIDUpper) // Use Upper in error
	}
	inputVuln := inputData.Vulnerabilities[0]
	if len(inputData.Vulnerabilities) > 1 {
		log.Printf("WARN: [%s] API returned multiple vulnerabilities (%d). Processing only first.", cveIDUpper, len(inputData.Vulnerabilities)) // Use Upper
	}
	// Check using uppercase comparison now
	if returnedIDUpper := strings.ToUpper(inputVuln.CVE.ID); returnedIDUpper != cveIDUpper {
		log.Printf("WARN: [%s] API returned different CVE ID (%s) than requested.", cveIDUpper, inputVuln.CVE.ID) // Use Upper
	}

	log.Printf("DEBUG: [%s] Transforming vulnerability data", cveIDUpper) // Use Upper
	outputCVE := transformCve(inputVuln.CVE)                              // Pass inner CVE
	log.Printf("DEBUG: [%s] Transformation complete", cveIDUpper)         // Use Upper
	return &outputCVE, nil
}

// fetchNVDDataWithRetry performs the HTTP GET with retries, enhanced timeout confirmation, and uppercase logging.
func fetchNVDDataWithRetry(ctx context.Context, logPrefix, cveIDForAPI, apiKey string) ([]byte, error) {
	// logPrefix is now expected to be the UPPERCASE CVE ID
	// cveIDForAPI is also UPPERCASE
	apiURL := fmt.Sprintf("%s?cveId=%s", nvdBaseURL, cveIDForAPI)
	var lastErr error
	configuredTimeout := time.Duration(cfg.RequestTimeoutSec) * time.Second

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		// Check parent context before starting attempt or sleep
		if err := ctx.Err(); err != nil {
			log.Printf("WARN: [%s] Parent context cancelled before attempt %d: %v", logPrefix, attempt+1, err) // Use attempt+1 for user-facing log
			return nil, err
		}

		if attempt > 0 {
			backoffDuration := time.Duration(cfg.InitialBackoffSec) * time.Second * time.Duration(math.Pow(2, float64(attempt-1)))
			log.Printf("WARN: [%s] Retrying request (attempt %d/%d) after error: %v. Waiting %v", logPrefix, attempt+1, cfg.MaxRetries+1, lastErr, backoffDuration)
			select {
			case <-time.After(backoffDuration):
				// Continue
			case <-ctx.Done():
				log.Printf("WARN: [%s] Parent context cancelled during backoff sleep: %v", logPrefix, ctx.Err())
				return nil, ctx.Err()
			}
		}

		// Create request context WITH THE TIMEOUT for this specific attempt
		reqCtx, cancelReq := context.WithTimeout(ctx, configuredTimeout)
		// *** We defer cancelReq immediately after creating reqCtx ***
		// This ensures it's called even if NewRequestWithContext fails (unlikely)
		// or if errors occur before httpClient.Do
		defer cancelReq()

		req, err := http.NewRequestWithContext(reqCtx, "GET", apiURL, nil)
		if err != nil {
			// No need to call cancelReq here, defer handles it.
			return nil, fmt.Errorf("[%s] create request error (attempt %d): %w", logPrefix, attempt+1, err)
		}

		if apiKey != "" {
			req.Header.Add("apiKey", apiKey)
		}
		req.Header.Add("User-Agent", userAgent)

		log.Printf("INFO: [%s] Requesting NVD API (attempt %d/%d, timeout: %v)", logPrefix, attempt+1, cfg.MaxRetries+1, configuredTimeout)
		resp, err := httpClient.Do(req) // Execute request with reqCtx

		// --- Analyze httpClient.Do errors ---
		if err != nil {
			// Check if the specific error is context.DeadlineExceeded from reqCtx
			if errors.Is(err, context.DeadlineExceeded) {
				// CONFIRMATION: Timeout occurred during connection/headers phase
				timeoutErr := fmt.Errorf("[%s] request timeout (%v) exceeded during HTTP Do (attempt %d): %w", logPrefix, configuredTimeout, attempt+1, err)
				log.Printf("WARN: %v", timeoutErr)
				lastErr = timeoutErr
				// continue // Retry on timeout
			} else if errors.Is(err, context.Canceled) {
				// Could be reqCtx cancelled by parent ctx, or other cancellation
				// Check if parent context (ctx) caused the cancellation
				if ctx.Err() != nil {
					log.Printf("WARN: [%s] Parent context cancelled during HTTP Do (attempt %d): %v", logPrefix, attempt+1, ctx.Err())
					return nil, ctx.Err() // Exit if parent is done
				}
				// Otherwise, likely specific reqCtx cancellation not due to its deadline
				lastErr = fmt.Errorf("[%s] request cancelled during HTTP Do (attempt %d): %w", logPrefix, attempt+1, err)
				log.Printf("WARN: %v", lastErr)
				// continue // Assume retryable if parent not cancelled?
			} else {
				// Other network/client errors (DNS, connection refused etc.)
				lastErr = fmt.Errorf("[%s] request execution error (attempt %d): %w", logPrefix, attempt+1, err)
				log.Printf("WARN: [%s] HTTP request failed (attempt %d), will retry: %v", logPrefix, attempt+1, err)
				// continue // Retry generic client errors
			}
			// No need to call cancelReq, defer handles it.
			continue // Go to next retry attempt
		}

		// If we got a response, ensure the body will be closed
		bodyCloseFunc := resp.Body.Close
		defer func() { _ = bodyCloseFunc() }() // Use defer closer

		statusCode := resp.StatusCode
		log.Printf("DEBUG: [%s] Received NVD response (attempt %d, status: %d)", logPrefix, attempt+1, statusCode)

		// --- Handle Status Codes ---
		switch {
		case statusCode == http.StatusOK:
			// Success status, proceed to read body below
		case statusCode == http.StatusNotFound:
			lastErr = fmt.Errorf("[%s] CVE not found at NVD (status %d)", logPrefix, statusCode)
			log.Printf("WARN: [%s] %v", logPrefix, lastErr)
			return nil, lastErr // Don't retry 404
		case statusCode == http.StatusTooManyRequests || statusCode == http.StatusForbidden:
			lastErr = fmt.Errorf("[%s] retryable NVD API error (status %d)", logPrefix, statusCode)
			log.Printf("WARN: [%s] NVD API returned retryable status %d, will backoff and retry", logPrefix, statusCode)
			continue // Retry
		case statusCode >= 500:
			lastErr = fmt.Errorf("[%s] NVD server error (status %d)", logPrefix, statusCode)
			log.Printf("WARN: [%s] NVD API returned server error %d, will backoff and retry", logPrefix, statusCode)
			continue // Retry
		default: // Other 4xx
			bodyBytes, _ := io.ReadAll(resp.Body)       // Read for error context
			_ = resp.Body.Close()                       // Close immediately after read
			bodyCloseFunc = func() error { return nil } // Prevent double close in defer
			lastErr = fmt.Errorf("[%s] non-retryable NVD client error (status %d)", logPrefix, statusCode)
			if len(bodyBytes) > 0 {
				lastErr = fmt.Errorf("%w - Body: %s", lastErr, limitString(string(bodyBytes), 200))
			}
			log.Printf("ERROR: [%s] Received non-retryable client error %d from NVD: %v", logPrefix, statusCode, lastErr)
			return nil, lastErr // Don't retry
		}

		// --- Read Body (only if status was OK) ---
		log.Printf("DEBUG: [%s] Reading response body (status %d)...", logPrefix, statusCode)
		bodyBytes, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()                       // Close body immediately after read attempt
		bodyCloseFunc = func() error { return nil } // Prevent double close in defer

		if readErr != nil {
			// --- Analyze body reading errors ---
			// Check DeadlineExceeded FIRST
			if errors.Is(readErr, context.DeadlineExceeded) {
				// *** CONFIRMATION LOG ***
				timeoutErr := fmt.Errorf("[%s] read body timeout (%v) exceeded (attempt %d, status %d): %w", logPrefix, configuredTimeout, attempt+1, statusCode, readErr)
				log.Printf("WARN: %v", timeoutErr)
				lastErr = timeoutErr
				// continue // Retry timeout during body read
			} else if errors.Is(readErr, context.Canceled) {
				// Check if parent context caused cancellation
				if ctx.Err() != nil {
					log.Printf("WARN: [%s] Parent context cancelled during body read (attempt %d, status %d): %v", logPrefix, attempt+1, statusCode, ctx.Err())
					return nil, ctx.Err() // Exit if parent is done
				}
				// Otherwise, reqCtx likely cancelled, maybe retry
				lastErr = fmt.Errorf("[%s] read body cancelled (attempt %d, status %d): %w", logPrefix, attempt+1, statusCode, readErr)
				log.Printf("WARN: %v", lastErr)
				// continue
			} else {
				// Other generic I/O error
				lastErr = fmt.Errorf("[%s] read body error (attempt %d, status %d): %w", logPrefix, attempt+1, statusCode, readErr)
				log.Printf("WARN: [%s] Failed to read response body (attempt %d), will retry: %v", logPrefix, attempt+1, readErr)
				// continue
			}
			continue // Go to next retry attempt for any read error
		}

		// Success: status was 200 OK and body read succeeded
		log.Printf("INFO: [%s] Successfully fetched and read data from NVD (attempt %d)", logPrefix, attempt+1)
		return bodyBytes, nil // SUCCESS

	} // End retry loop

	// If loop finished without success
	log.Printf("ERROR: [%s] Request failed after maximum retries (%d)", logPrefix, cfg.MaxRetries)
	return nil, fmt.Errorf("[%s] retries exceeded after %d attempts: %w", logPrefix, cfg.MaxRetries, lastErr)
}

// --- Transformation Logic (Unchanged) ---
func transformCve(sourceCve InputCVE) TargetCve {
	target := TargetCve{
		ID:                    strings.ToUpper(sourceCve.ID), // Ensure ID is uppercase
		SourceIdentifier:      sourceCve.SourceIdentifier,
		Published:             sourceCve.Published,
		LastModified:          sourceCve.LastModified,
		VulnStatus:            sourceCve.VulnStatus,
		CisaExploitAdd:        sourceCve.CisaExploitAdd,
		CisaActionDue:         sourceCve.CisaActionDue,
		CisaRequiredAction:    sourceCve.CisaRequiredAction,
		CisaVulnerabilityName: sourceCve.CisaVulnerabilityName,
	}
	for _, desc := range sourceCve.Descriptions {
		if desc.Lang == "en" {
			target.Description = desc.Value
			break
		}
	}
	if target.Description == "" && len(sourceCve.Descriptions) > 0 {
		log.Printf("WARN: [%s] No English description found.", target.ID) // Log using uppercase target ID
	}
	var collectedMetrics []interface{}
	if sourceCve.Metrics != nil {
		collectedMetrics = make([]interface{}, 0)
		if len(sourceCve.Metrics.CvssMetricV2) > 0 {
			for _, srcV2 := range sourceCve.Metrics.CvssMetricV2 {
				targetV2 := TargetCvssMetricV2{Source: srcV2.Source, Type: srcV2.Type, CvssData: TargetCvssDataV2{Version: srcV2.CvssData.Version, VectorString: srcV2.CvssData.VectorString, AccessVector: srcV2.CvssData.AccessVector, AccessComplexity: srcV2.CvssData.AccessComplexity, Authentication: srcV2.CvssData.Authentication, ConfidentialityImpact: srcV2.CvssData.ConfidentialityImpact, IntegrityImpact: srcV2.CvssData.IntegrityImpact, AvailabilityImpact: srcV2.CvssData.AvailabilityImpact, BaseScore: srcV2.CvssData.BaseScore, BaseSeverity: srcV2.BaseSeverity}, ExploitabilityScore: srcV2.ExploitabilityScore, ImpactScore: srcV2.ImpactScore, AcInsufInfo: srcV2.AcInsufInfo, ObtainAllPrivilege: srcV2.ObtainAllPrivilege, ObtainUserPrivilege: srcV2.ObtainUserPrivilege, ObtainOtherPrivilege: srcV2.ObtainOtherPrivilege, UserInteractionRequired: srcV2.UserInteractionRequired}
				collectedMetrics = append(collectedMetrics, targetV2)
			}
		}
		if len(sourceCve.Metrics.CvssMetricV31) > 0 {
			for _, srcV31 := range sourceCve.Metrics.CvssMetricV31 {
				targetV31 := TargetCvssMetricV31{Source: srcV31.Source, Type: srcV31.Type, CvssData: TargetCvssDataV31{Version: srcV31.CvssData.Version, VectorString: srcV31.CvssData.VectorString, AttackVector: srcV31.CvssData.AttackVector, AttackComplexity: srcV31.CvssData.AttackComplexity, PrivilegesRequired: srcV31.CvssData.PrivilegesRequired, UserInteraction: srcV31.CvssData.UserInteraction, Scope: srcV31.CvssData.Scope, ConfidentialityImpact: srcV31.CvssData.ConfidentialityImpact, IntegrityImpact: srcV31.CvssData.IntegrityImpact, AvailabilityImpact: srcV31.CvssData.AvailabilityImpact, BaseScore: srcV31.CvssData.BaseScore, BaseSeverity: srcV31.CvssData.BaseSeverity}, ExploitabilityScore: srcV31.ExploitabilityScore, ImpactScore: srcV31.ImpactScore}
				collectedMetrics = append(collectedMetrics, targetV31)
			}
		}
		if len(sourceCve.Metrics.CvssMetricV40) > 0 {
			for _, srcV40 := range sourceCve.Metrics.CvssMetricV40 {
				targetV40 := TargetCvssMetricV40{Source: srcV40.Source, Type: srcV40.Type, CvssData: TargetCvssDataV40{Version: srcV40.CvssData.Version, VectorString: srcV40.CvssData.VectorString, BaseScore: srcV40.CvssData.BaseScore, BaseSeverity: srcV40.CvssData.BaseSeverity, AttackVector: srcV40.CvssData.AttackVector, AttackComplexity: srcV40.CvssData.AttackComplexity, AttackRequirements: srcV40.CvssData.AttackRequirements, PrivilegesRequired: srcV40.CvssData.PrivilegesRequired, UserInteraction: srcV40.CvssData.UserInteraction, VulnConfidentialityImpact: srcV40.CvssData.VulnConfidentialityImpact, VulnIntegrityImpact: srcV40.CvssData.VulnIntegrityImpact, VulnAvailabilityImpact: srcV40.CvssData.VulnAvailabilityImpact, SubConfidentialityImpact: srcV40.CvssData.SubConfidentialityImpact, SubIntegrityImpact: srcV40.CvssData.SubIntegrityImpact, SubAvailabilityImpact: srcV40.CvssData.SubAvailabilityImpact}}
				collectedMetrics = append(collectedMetrics, targetV40)
			}
		}
	}
	if len(collectedMetrics) > 0 {
		target.Metrics = collectedMetrics
	}
	if len(sourceCve.Weaknesses) > 0 {
		target.Weaknesses = make([]TargetWeakness, len(sourceCve.Weaknesses))
		for i, srcWeakness := range sourceCve.Weaknesses {
			target.Weaknesses[i] = TargetWeakness{Source: srcWeakness.Source, Type: srcWeakness.Type, Description: srcWeakness.Description}
		}
	}
	return target
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
	idsMap := make(map[string]bool)
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
			idsMap[val] = true
		} else {
			zap.L().Warn("Unexpected type/nil for package_name", zap.Int("row", i))
		}
	}

	var ids []string
	for id := range idsMap {
		ids = append(ids, id)
	}

	return ids, nil
}

func sendCveDetails(esClient og_es_sdk.Client, request tasks.TaskRequest, r *TargetCve) (err error) {
	if r == nil {
		return nil
	}
	esResult := &es.TaskResult{
		PlatformID:   fmt.Sprintf("%s:::%s:::%s", request.TaskDefinition.TaskType, "cve_details", r.UniqueID()),
		ResourceID:   r.UniqueID(),
		ResourceName: r.ID,
		Description:  r, // Embed the full SbomVulnerabilities struct
		ResultType:   strings.ToLower("cve_details"),
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

func checkNvdApiKeyHealth(ctx context.Context, apiKey string, httpClient *http.Client, timeout time.Duration) error {
	logPrefix := "[API Key Health Check]"
	// Use a CVE ID format that is highly unlikely to ever exist
	testCveID := "CVE-2010-0001"
	apiURL := fmt.Sprintf("%s?cveId=%s", nvdBaseURL, testCveID)
	// Use the provided timeout directly
	configuredTimeout := timeout

	// Create a context specifically for this health check request
	reqCtx, cancelReq := context.WithTimeout(ctx, configuredTimeout)
	defer cancelReq() // Ensure cancellation is called

	req, err := http.NewRequestWithContext(reqCtx, "GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("%s failed to create request: %w", logPrefix, err)
	}

	// Add API key header ONLY if a key is provided.
	if apiKey != "" {
		req.Header.Add("apiKey", apiKey)
		log.Printf("DEBUG: %s Testing with provided API Key.", logPrefix)
	} else {
		log.Printf("DEBUG: %s Testing without API Key (anonymous access).", logPrefix)
	}
	req.Header.Add("User-Agent", userAgent) // Assumes userAgent is initialized globally

	log.Printf("INFO: %s Sending request to NVD API (timeout: %v)", logPrefix, configuredTimeout)
	resp, err := httpClient.Do(req) // Assumes httpClient is initialized globally

	// --- Analyze errors from httpClient.Do ---
	if err != nil {
		// Check if the error is due to the request context's deadline
		if errors.Is(err, context.DeadlineExceeded) {
			// Use the passed timeout value in the error message
			timeoutErr := fmt.Errorf("%s request timeout (%v) exceeded: %w", logPrefix, configuredTimeout, err)
			log.Printf("WARN: %v", timeoutErr)
			return timeoutErr
		}
		// Check if the error is due to parent context cancellation
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			log.Printf("WARN: %s Parent context cancelled during request: %v", logPrefix, ctx.Err())
			return ctx.Err() // Return parent context error
		}
		// Other network/client errors
		execErr := fmt.Errorf("%s request execution failed: %w", logPrefix, err)
		log.Printf("WARN: %v", execErr)
		return execErr
	}

	// Ensure the response body is always closed
	defer resp.Body.Close()

	statusCode := resp.StatusCode
	log.Printf("DEBUG: %s Received NVD response status: %d", logPrefix, statusCode)

	// --- Analyze Status Codes ---
	switch statusCode {
	case http.StatusOK:
		log.Printf("WARN: %s Received status 200 OK for non-existent CVE %s. Assuming API key is functional, but behavior is unexpected.", logPrefix, testCveID)
		return nil
	case http.StatusNotFound:
		log.Printf("INFO: %s Received status 404 Not Found (expected). API key appears valid and NVD API is reachable.", logPrefix)
		return fmt.Errorf("API Key not found")
	case http.StatusForbidden:
		err := fmt.Errorf("%s received status 403 Forbidden. API key is likely invalid or expired", logPrefix)
		log.Printf("ERROR: %v", err)
		return err // Unhealthy credentials
	case http.StatusTooManyRequests:
		err := fmt.Errorf("%s received status 429 Too Many Requests. Rate limited, cannot confirm key validity", logPrefix)
		log.Printf("WARN: %v", err)
		return err // Cannot confirm health
	case http.StatusInternalServerError:
		err := fmt.Errorf("%s received status 500 Internal Server Error. NVD API server issue", logPrefix)
		log.Printf("WARN: %v", err)
		return err // Cannot confirm health due to server issue
	case http.StatusServiceUnavailable:
		err := fmt.Errorf("%s received status 503 Service Unavailable. NVD API server issue", logPrefix)
		log.Printf("WARN: %v", err)
		return err // Cannot confirm health due to server issue
	default:
		err := fmt.Errorf("%s received unexpected status code %d", logPrefix, statusCode)
		log.Printf("WARN: %v", err)
		return err // Cannot confirm health
	}
}

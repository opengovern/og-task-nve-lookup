package worker

import (
	"context"
	"encoding/json"
	"errors" // Added import
	"fmt"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/opengovern/og-task-nve-lookup/envs"
	"github.com/opengovern/og-task-nve-lookup/task"
	"github.com/opengovern/og-util/pkg/jq"
	"github.com/opengovern/og-util/pkg/opengovernance-es-sdk"
	"github.com/opengovern/og-util/pkg/tasks"
	"github.com/opengovern/opensecurity/services/tasks/db/models"
	"github.com/opengovern/opensecurity/services/tasks/scheduler"
	"go.uber.org/zap"
	"strconv"
	"time"
)

type Worker struct {
	logger   *zap.Logger
	jq       *jq.JobQueue
	esClient opengovernance.Client
}

func NewWorker(
	logger *zap.Logger,
	ctx context.Context,
) (*Worker, error) {
	jq, err := jq.New(envs.NatsURL, logger)
	if err != nil {
		logger.Error("failed to create job queue", zap.Error(err), zap.String("url", envs.NatsURL))
		return nil, err
	}
	logger.Info("Ensuring stream exists", zap.String("stream", envs.StreamName),
		zap.Strings("topics", []string{envs.TopicName, envs.ResultTopicName}))
	if err := jq.Stream(ctx, envs.StreamName, "task job queue", []string{envs.TopicName, envs.ResultTopicName}, 100); err != nil {
		logger.Error("failed to create stream", zap.Error(err))
		return nil, err
	}
	isOnAks := false
	isOnAks, _ = strconv.ParseBool(envs.ESIsOnAks)
	isOpenSearch := false
	isOpenSearch, _ = strconv.ParseBool(envs.ESIsOpenSearch)
	esClient, err := opengovernance.NewClient(opengovernance.ClientConfig{
		Addresses:     []string{envs.ESAddress},
		Username:      &envs.ESUsername,
		Password:      &envs.ESPassword,
		IsOnAks:       &isOnAks,
		IsOpenSearch:  &isOpenSearch,
		AwsRegion:     &envs.ESAwsRegion,
		AssumeRoleArn: &envs.ESAssumeRoleArn,
	})
	if err != nil {
		logger.Error("failed to create ES client", zap.Error(err))
		return nil, err
	}
	w := &Worker{
		logger:   logger,
		jq:       jq,
		esClient: esClient,
	}
	return w, nil
}

func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("starting to consume", zap.String("url", envs.NatsURL), zap.String("consumer", envs.NatsConsumer),
		zap.String("stream", envs.StreamName), zap.String("topic", envs.TopicName))

	consumeCtx, err := w.jq.ConsumeWithConfig(ctx, envs.NatsConsumer, envs.StreamName, []string{envs.TopicName}, jetstream.ConsumerConfig{
		Replicas:          1,
		AckPolicy:         jetstream.AckExplicitPolicy,
		DeliverPolicy:     jetstream.DeliverAllPolicy,
		MaxAckPending:     -1,
		AckWait:           time.Minute * 30,
		InactiveThreshold: time.Hour,
	}, []jetstream.PullConsumeOpt{
		jetstream.PullMaxMessages(1),
	}, func(msg jetstream.Msg) {
		w.logger.Info("received a new job")

		err := w.ProcessMessage(ctx, msg)
		if err != nil {
			// Log error from ProcessMessage itself (e.g., initial setup failure)
			// Note: Errors during task.RunTask are handled within ProcessMessage's defer
			w.logger.Error("failed during message processing setup", zap.Error(err))
		}

		// Ack is always sent by Run after ProcessMessage finishes or fails setup
		if ackErr := msg.Ack(); ackErr != nil {
			w.logger.Error("failed to send the ack message", zap.Error(ackErr))
		}

		w.logger.Info("processing a job completed")
	})
	if err != nil {
		w.logger.Error("failed to start consuming messages", zap.Error(err))
		return err
	}

	w.logger.Info("consuming messages...")

	<-ctx.Done()
	w.logger.Info("Main context cancelled, draining consumer...")
	consumeCtx.Drain()
	w.logger.Info("Consumer stopped.")

	return nil
}

func (w *Worker) ProcessMessage(ctx context.Context, msg jetstream.Msg) (err error) {
	var request tasks.TaskRequest
	if err = json.Unmarshal(msg.Data(), &request); err != nil {
		w.logger.Error("Failed to unmarshal TaskRequest", zap.Error(err))
		return err
	}

	runID := request.TaskDefinition.RunID
	msgLogger := w.logger.With(zap.Uint("runID", runID))

	response := &scheduler.TaskResponse{
		RunID:  runID,
		Status: models.TaskRunStatusInProgress,
	}

	ctxWithCancel, cancel := context.WithCancel(ctx)
	defer cancel()

	cancelSubject := tasks.GetTaskRunCancelSubject(envs.TopicName, runID)
	var subscription *nats.Subscription
	subscription, err = w.jq.Subscribe(cancelSubject, func(m *nats.Msg) {
		msgLogger.Info("Received cancellation request via NATS subject", zap.String("subject", cancelSubject))
		cancel()
	})
	if err != nil {
		msgLogger.Error("failed to subscribe to cancellation subject", zap.Error(err), zap.String("subject", cancelSubject))
		return err
	} else {
		msgLogger.Info("Subscribed to cancellation subject", zap.String("subject", cancelSubject))
		defer func() {
			if unsubErr := subscription.Unsubscribe(); unsubErr != nil {
				msgLogger.Error("failed to unsubscribe from cancellation subject", zap.Error(unsubErr), zap.String("subject", cancelSubject))
			} else {
				msgLogger.Info("Unsubscribed from cancellation subject", zap.String("subject", cancelSubject))
			}
		}()
	}

	defer func() {
		finalStatus := models.TaskRunStatusFinished
		failureMsg := ""

		if err != nil {
			if errors.Is(err, context.Canceled) {
				if ctxWithCancel.Err() == context.Canceled {
					finalStatus = models.TaskRunStatusCancelled
					msgLogger.Warn("Job execution was cancelled", zap.Error(err))
				} else {
					finalStatus = models.TaskRunStatusFailed
					failureMsg = "Task run cancelled (worker shutdown?)"
					msgLogger.Warn("Job execution cancelled by parent context", zap.Error(err))
				}
			} else {
				finalStatus = models.TaskRunStatusFailed
				failureMsg = err.Error()
				msgLogger.Error("Task execution resulted in error", zap.Error(err))
			}
		} else {
			finalStatus = models.TaskRunStatusFinished
			msgLogger.Info("Task execution finished successfully")
		}

		response.Status = finalStatus
		response.FailureMessage = failureMsg

		responseJson, marshalErr := json.Marshal(response)
		if marshalErr != nil {
			msgLogger.Error("failed to create final job result json", zap.Error(marshalErr))
			return
		}

		produceCtx, produceCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer produceCancel()

		msgId := fmt.Sprintf("task-run-result-%d", runID)
		if _, pubErr := w.jq.Produce(produceCtx, envs.ResultTopicName, responseJson, msgId); pubErr != nil {
			msgLogger.Error("failed to publish final job result", zap.String("jobResult", string(responseJson)), zap.Error(pubErr))
		} else {
			msgLogger.Info("Published final job result", zap.String("status", string(finalStatus)), zap.String("msgId", msgId))
		}
	}()

	responseJson, err := json.Marshal(response)
	if err != nil {
		msgLogger.Error("failed to create initial InProgress response json", zap.Error(err))
		return err
	}
	msgId := fmt.Sprintf("task-run-inprogress-%d", runID)
	if _, err = w.jq.Produce(ctx, envs.ResultTopicName, responseJson, msgId); err != nil { // Use original ctx
		msgLogger.Error("failed to publish initial InProgress job status", zap.String("response", string(responseJson)), zap.Error(err))
		return err
	}
	msgLogger.Info("Published initial InProgress job status via Produce")

	msgLogger.Info("Sending initial InProgress ACK extension")
	if err = msg.InProgress(); err != nil {
		msgLogger.Error("failed to send the initial InProgress ACK notification", zap.Error(err))
		err = nil
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				msgLogger.Debug("Sending periodic InProgress ACK extension")
				if pingErr := msg.InProgress(); pingErr != nil {
					msgLogger.Error("failed to send periodic InProgress ACK notification", zap.Error(pingErr))
				}
			case <-ctxWithCancel.Done():
				msgLogger.Info("Job context cancelled or finished, stopping InProgress ticker.")
				return
			}
		}
	}()

	msgLogger.Info("Starting task execution")
	err = task.RunTask(ctxWithCancel, w.jq, envs.InventoryServiceEndpoint, w.esClient, msgLogger, request, response)

	return err
}

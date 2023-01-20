package log

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	CtxKeyUniqId      = "id"
	CtxKeyApiMethod   = "method"
	CtxKeyReqId       = "reqid"
	CtxKeyUserId      = "user_id"
	CtxKeyConn        = "conn"
	CtxKeyDuration    = "duration"
	CtxKeyBlockNumber = "block_num"
	CtxKeyBlockHash   = "block_hash"
)

// TODO: Allow registering arbitrary keys.
var registeredKeys = []string{
	CtxKeyApiMethod,
	CtxKeyReqId,
	CtxKeyUserId,
	CtxKeyConn,
	CtxKeyDuration,
	CtxKeyUniqId,
	CtxKeyBlockNumber,
	CtxKeyBlockHash,
}

const FatalLevel = logrus.FatalLevel
const ErrorLevel = logrus.ErrorLevel
const InfoLevel = logrus.InfoLevel
const DebugLevel = logrus.DebugLevel
const TraceLevel = logrus.TraceLevel

type Entry = logrus.Entry

func GetLog(ctx context.Context) *logrus.Entry {
	entry := logrus.WithContext(ctx)

	for _, key := range registeredKeys {
		if value := ctx.Value(key); value != nil {
			entry = entry.WithField(key, value)
		}
	}
	return entry
}

func Fatalx(ctx context.Context, args ...interface{}) {
	GetLog(ctx).Fatal(args...)
}

func Errorx(ctx context.Context, args ...interface{}) {
	GetLog(ctx).Error(args...)
}

func Warnx(ctx context.Context, args ...interface{}) {
	GetLog(ctx).Warn(args...)
}

func Infox(ctx context.Context, args ...interface{}) {
	GetLog(ctx).Info(args...)
}

func Debugx(ctx context.Context, args ...interface{}) {
	GetLog(ctx).Debug(args...)
}

func Tracex(ctx context.Context, args ...interface{}) {
	GetLog(ctx).Trace(args...)
}

func Errorxf(ctx context.Context, format string, args ...interface{}) {
	GetLog(ctx).Errorf(format, args...)
}

func Warnxf(ctx context.Context, format string, args ...interface{}) {
	GetLog(ctx).Warnf(format, args...)
}

func Infoxf(ctx context.Context, format string, args ...interface{}) {
	GetLog(ctx).Infof(format, args...)
}
func Debugxf(ctx context.Context, format string, args ...interface{}) {
	GetLog(ctx).Debugf(format, args...)
}
func Tracexf(ctx context.Context, format string, args ...interface{}) {
	GetLog(ctx).Tracef(format, args...)
}

func Fatal(args ...interface{}) {
	logrus.Fatal(args...)
}
func Error(args ...interface{}) {
	logrus.Error(args...)
}

func Warn(args ...interface{}) {
	logrus.Warn(args...)
}

func Info(args ...interface{}) {
	logrus.Info(args...)
}

func Debug(args ...interface{}) {
	logrus.Debug(args...)
}

func Trace(args ...interface{}) {
	logrus.Trace(args...)
}
func Fatalf(format string, args ...interface{}) {
	logrus.Fatalf(format, args...)
}
func Errorf(format string, args ...interface{}) {
	logrus.Errorf(format, args...)
}

func Warnf(format string, args ...interface{}) {
	logrus.Warnf(format, args...)
}

func Infof(format string, args ...interface{}) {
	logrus.Infof(format, args...)
}
func Debugf(format string, args ...interface{}) {
	logrus.Debugf(format, args...)
}
func Tracef(format string, args ...interface{}) {
	logrus.Tracef(format, args...)
}

func WithError(err error) *Entry {
	return logrus.WithError(err)
}

func WithField(field string, value interface{}) *Entry {
	return logrus.WithField(field, value)
}

func Init() error {
	// Set the output.
	viper.BindEnv("logrus.file", "LOGRUS_FILE")
	logFile := viper.GetString("logrus.file")
	if logFile != "" {
		file, err := os.OpenFile(logFile,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err == nil {
			logrus.Infof("Directing output to %s", logFile)
			logrus.SetOutput(file)
		} else {
			logrus.SetOutput(os.Stdout)
			logrus.Info("Failed to logrus.to file, using default stdout")
		}
	} else {
		logrus.SetOutput(os.Stdout)
	}

	// Set the level.
	viper.BindEnv("logrus.level", "LOGRUS_LEVEL")
	lvl, err := logrus.ParseLevel(viper.GetString("logrus.level"))
	if err != nil {
		return err
	}
	logrus.SetLevel(lvl)

	formatter := &logrus.TextFormatter{}
	// Show file/line number only at Trace level.
	if lvl >= TraceLevel {
		logrus.SetReportCaller(true)

		// We need to exclude this wrapper code, logrus.us itself, and the runtime from the stack to show anything useful.
		// cf. https://github.com/sirupsen/logrus.us/pull/973
		formatter.CallerPrettyfier = func(frame *runtime.Frame) (function string, file string) {
			pcs := make([]uintptr, 50)
			_ = runtime.Callers(0, pcs)
			frames := runtime.CallersFrames(pcs)

			// Filter logrus.wrapper / logrus.us / runtime frames.
			for next, again := frames.Next(); again; next, again = frames.Next() {
				if !strings.Contains(next.File, "sirupsen/logrus.us") &&
					!strings.HasPrefix(next.Function, "runtime.") &&
					!strings.Contains(next.File, "ipld-eth-server/pkg/logrus") {
					return next.Function, fmt.Sprintf("%s:%d", next.File, next.Line)
				}
			}

			// Fallback to the raw info.
			return frame.Function, fmt.Sprintf("%s:%d", frame.File, frame.Line)
		}
	}

	logrus.SetFormatter(formatter)
	logrus.Info("Log level set to ", lvl.String())
	return nil
}

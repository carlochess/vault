package paramstore

import (
	"context"
	b64 "encoding/base64"
	log "github.com/hashicorp/go-hclog"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	metrics "github.com/armon/go-metrics"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/hashicorp/errwrap"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/helper/awsutil"
	"github.com/hashicorp/vault/helper/consts"
	"github.com/hashicorp/vault/physical"
)

const (
	DefaultRegion    = "us-east-1"
	ParamStorePrefix = "/vault/"
)

var _ physical.Backend = (*ParamStoreBackend)(nil)

type ParamStoreBackend struct {
	client     *ssm.SSM
	logger     log.Logger
	permitPool *physical.PermitPool
        path       string
}

func NewParamStoreBackend(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	accessKey, ok := conf["access_key"]
        if !ok {
           accessKey = ""
        }

	secretKey, ok := conf["secret_key"]
        if !ok {
           secretKey = ""
        }

        sessionToken, ok := conf["session_token"]
        if !ok {
           sessionToken = ""
        }

        credsConfig := &awsutil.CredentialsConfig{
	   AccessKey:    accessKey,
	   SecretKey:    secretKey,
           SessionToken: sessionToken,
	}

	creds, err := credsConfig.GenerateCredentialChain()
	if err != nil {
		return nil, err
	}

	region := "us-east-1"
	regionFromUser, ok := conf["region"]
        if ok {
		region = regionFromUser
	}

	pooledTransport := cleanhttp.DefaultPooledTransport()
	pooledTransport.MaxIdleConnsPerHost = consts.ExpirationRestoreWorkerCount

	awsConf := aws.NewConfig().
		WithCredentials(creds).
		WithRegion(region).
		WithHTTPClient(&http.Client{
			Transport: pooledTransport,
		})

	awsSession, err := session.NewSession(awsConf)
	if err != nil {
		return nil, errwrap.Wrapf("Could not establish AWS session: {{err}}", err)
	}

	path := ParamStorePrefix
	pathFromUser, ok := conf["path"]
        if ok {
		path = pathFromUser
	}
	client := ssm.New(awsSession)

	return &ParamStoreBackend{
		client: client,
		logger: logger,
                path: path,
	}, nil
}

func (d *ParamStoreBackend) Put(ctx context.Context, entry *physical.Entry) error {
	defer metrics.MeasureSince([]string{"ParamStore", "put"}, time.Now())
	typestr := "String"
	overwrite := true
	key := d.nodePath(entry.Key)
	val := b64.StdEncoding.EncodeToString(entry.Value)
	d.logger.Info("Inserting", "key", key, "value", val)
	_, err := d.client.PutParameter(&ssm.PutParameterInput{
		Name:      aws.String(key),
		Value:     aws.String(val),
		Type:      &typestr,
		Overwrite: &overwrite,
	})

	return err
}

func (d *ParamStoreBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	defer metrics.MeasureSince([]string{"ParamStore", "get"}, time.Now())
	wDecrypt := true
	keyn := d.nodePath(key)
	d.logger.Info("Getting", "Key", keyn)
	resp, err := d.client.GetParameter(&ssm.GetParameterInput{
		Name:           &keyn,
		WithDecryption: &wDecrypt,
	})

	if err != nil {
		if err.(awserr.Error).Code() == ssm.ErrCodeParameterNotFound {
			return nil, nil // err
		}
		if err.(awserr.Error).Code() != ssm.ErrCodeParameterNotFound {
			return nil, err
		}
		if resp.Parameter == nil {
			return nil, nil
		}
	}
	record := resp.Parameter
	value, _ := b64.StdEncoding.DecodeString(*record.Value)
	d.logger.Info("Getting Value", "val", *record.Value)
	return &physical.Entry{
		Key:   *record.Name,
		Value: value,
	}, nil
}

func (d *ParamStoreBackend) Delete(ctx context.Context, key string) error {
	defer metrics.MeasureSince([]string{"ParamStore", "delete"}, time.Now())
	key = d.nodePath(key)
	d.logger.Info("Delete", "Key", key)
	_, err := d.client.DeleteParameter(&ssm.DeleteParameterInput{
		Name: &key,
	})

	return err
}

func (d *ParamStoreBackend) List(ctx context.Context, prefix string) ([]string, error) {
	defer metrics.MeasureSince([]string{"ParamStore", "list"}, time.Now())
	prefix = d.nodePathDir(prefix)
	d.logger.Info("List", "Prefix", prefix)
	keys := []string{}

	params := &ssm.GetParametersByPathInput{
		Path: aws.String(prefix),
	}

	err := d.client.GetParametersByPathPages(params,
		func(page *ssm.GetParametersByPathOutput, lastPage bool) bool {
			if page != nil {
				d.logger.Info("Parameter length", "Param", len(page.Parameters), "Last Page?", lastPage)
				for _, parameter := range page.Parameters {
					// Avoid panic
					if parameter == nil {
						continue
					}
					key := strings.TrimPrefix(*parameter.Name, prefix)
					keys = append(keys, key)
				}
			}
			return true
		})

	if err != nil {
		return nil, err
	}
	sort.Strings(keys)

	d.logger.Info("List", "Prefix", prefix, "Keys", keys)

	return keys, nil
}

func (c *ParamStoreBackend) nodePath(key string) string {
	return filepath.Join(c.path, filepath.Dir(key), filepath.Base(key))
}

// nodePathDir returns an etcd directory path based on the given key.
func (c *ParamStoreBackend) nodePathDir(key string) string {
	return filepath.Join(c.path, key) + "/"
}


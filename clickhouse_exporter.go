package main // import "github.com/Percona-Lab/clickhouse_exporter"

import (
	"context"
	"crypto/tls"
	"flag"
	"net/http"
	"net/url"
	"os"

	"github.com/ClickHouse/clickhouse_exporter/exporter"
	"github.com/cloudflare/certinel/fswatcher"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/log"
)

var (
	listeningAddress    = flag.String("telemetry.address", ":9116", "Address on which to expose metrics.")
	metricsEndpoint     = flag.String("telemetry.endpoint", "/metrics", "Path under which to expose metrics.")
	clickhouseScrapeURI = flag.String("scrape_uri", "http://localhost:8123/", "URI to clickhouse http endpoint")
	insecure            = flag.Bool("insecure", true, "Ignore server certificate if using https")
	user                = os.Getenv("CLICKHOUSE_USER")
	password            = os.Getenv("CLICKHOUSE_PASSWORD")
	identityCertPath    = flag.String("identity.cert_path", "", "Path of identity TLS certificate to use for identification")
	identityKeyPath     = flag.String("identity.key_path", "", "Path of identity TLS certificate to use for identification")
)

func main() {
	flag.Parse()

	uri, err := url.Parse(*clickhouseScrapeURI)
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: *insecure,
		MinVersion:         tls.VersionTLS12,
	}

	if password == "" && *identityCertPath != "" {
		setupMTLS(tlsConfig)
	}

	e := exporter.NewExporter(*uri, tlsConfig, exporter.Credentials{
		User:     user,
		Password: password,
		CertPath: *identityCertPath,
		KeyPath:  *identityKeyPath,
	})
	prometheus.MustRegister(e)

	log.Printf("Starting Server: %s", *listeningAddress)
	http.Handle(*metricsEndpoint, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Clickhouse Exporter</title></head>
			<body>
			<h1>Clickhouse Exporter</h1>
			<p><a href="` + *metricsEndpoint + `">Metrics</a></p>
			</body>
			</html>`))
	})

	log.Fatal(http.ListenAndServe(*listeningAddress, nil))
}

func setupMTLS(tlsConfig *tls.Config) {
	certWatcher, err := fswatcher.New(*identityCertPath, *identityKeyPath)
	if err != nil {
		log.Errorf("could not set up cert watcher for certificate %s: %s", *identityCertPath, err.Error())
	} else {
		go func() {
			log.Infof("watching identity cert: %s, key file: %s", *identityCertPath, *identityKeyPath)
			err := certWatcher.Start(context.Background())
			if err != nil {
				log.Fatalf("cert watcher failed: %s", err.Error())
			}
		}()
		tlsConfig.GetClientCertificate = certWatcher.GetClientCertificate
	}
}

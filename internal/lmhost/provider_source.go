// SPDX-License-Identifier: MIT

package lmhost

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/apparentlymart/go-userdirs/userdirs"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/opentofu/svchost"
	"github.com/opentofu/svchost/disco"
	"github.com/opentofu/svchost/svcauth"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/command/cliconfig"
	"github.com/opentofu/opentofu/internal/getmodules"
	"github.com/opentofu/opentofu/internal/getproviders"
	"github.com/opentofu/opentofu/internal/httpclient"
	"github.com/opentofu/opentofu/internal/logging"
	"github.com/opentofu/opentofu/internal/oci"
	pluginDiscovery "github.com/opentofu/opentofu/internal/plugin/discovery"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func newRegistryHTTPClient(ctx context.Context, config *cliconfig.RegistryProtocolsConfig) *retryablehttp.Client {
	retryCount := 1
	timeout := 10 * time.Second
	if config != nil {
		retryCount = config.RetryCount
		if config.RequestTimeout > 0 {
			timeout = config.RequestTimeout
		}
	}
	client := httpclient.NewForRegistryRequests(ctx, retryCount, timeout)
	logOutput := logging.LogOutput()
	client.Logger = log.New(logOutput, "", log.Flags())
	return client
}

func newServiceDiscovery(ctx context.Context, registryClientConfig *cliconfig.RegistryProtocolsConfig, credSrc svcauth.CredentialsSource) *disco.Disco {
	registryHTTPClient := newRegistryHTTPClient(ctx, registryClientConfig)
	return disco.New(
		disco.WithHTTPClient(registryHTTPClient.HTTPClient),
		disco.WithCredentials(credSrc),
	)
}

func credentialsSource(config *cliconfig.Config) (svcauth.CredentialsSource, error) {
	if config == nil {
		return nil, nil
	}
	helperPlugins := pluginDiscovery.FindPlugins("credentials", globalPluginDirs())
	return config.CredentialsSource(helperPlugins)
}

func configureHostServices(services *disco.Disco, config *cliconfig.Config) {
	if services == nil || config == nil {
		return
	}
	for userHost, hostConfig := range config.Hosts {
		host, err := svchost.ForComparison(userHost)
		if err != nil {
			continue
		}
		services.ForceHostServices(host, hostConfig.Services)
	}
}

func globalPluginDirs() []string {
	var ret []string
	dirs, err := cliconfig.DataDirs()
	if err == nil {
		machineDir := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
		for _, dir := range dirs {
			ret = append(ret, filepath.Join(dir, "plugins"))
			ret = append(ret, filepath.Join(dir, "plugins", machineDir))
		}
	}
	return ret
}

func remoteModulePackageFetcher(ctx context.Context, getOCICredsPolicy oci.OCICredsPolicyBuilder) *getmodules.PackageFetcher {
	return getmodules.NewPackageFetcher(ctx, &modulePackageFetcherEnvironment{
		getOCICredsPolicy: getOCICredsPolicy,
	})
}

type modulePackageFetcherEnvironment struct {
	getOCICredsPolicy oci.OCICredsPolicyBuilder
}

func (m *modulePackageFetcherEnvironment) OCIRepositoryStore(ctx context.Context, registryDomainName string, repositoryPath string) (getmodules.OCIRepositoryStore, error) {
	credsPolicy, err := m.getOCICredsPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials configuration for OCI registries: %w", err)
	}
	return oci.GetOCIRepositoryStore(ctx, registryDomainName, repositoryPath, credsPolicy)
}

func buildProviderSource(
	ctx context.Context,
	configs []*cliconfig.ProviderInstallation,
	registryClientConfig *cliconfig.RegistryProtocolsConfig,
	services *disco.Disco,
	getOCICredsPolicy oci.OCICredsPolicyBuilder,
	searchRootDirs ...string,
) (getproviders.Source, tfdiags.Diagnostics) {
	if len(configs) == 0 {
		return implicitProviderSource(ctx, registryClientConfig, services, searchRootDirs...), nil
	}
	return explicitProviderSource(ctx, configs[0], registryClientConfig, services, getOCICredsPolicy)
}

func explicitProviderSource(
	ctx context.Context,
	config *cliconfig.ProviderInstallation,
	registryClientConfig *cliconfig.RegistryProtocolsConfig,
	services *disco.Disco,
	getOCICredsPolicy oci.OCICredsPolicyBuilder,
) (getproviders.Source, tfdiags.Diagnostics) {
	var diags tfdiags.Diagnostics
	var searchRules []getproviders.MultiSourceSelector

	for _, methodConfig := range config.Methods {
		source, moreDiags := providerSourceForCLIConfigLocation(ctx, methodConfig.Location, methodConfig.Retries, methodConfig.Trusted, registryClientConfig, services, getOCICredsPolicy)
		diags = diags.Append(moreDiags)
		if moreDiags.HasErrors() {
			continue
		}

		include, err := getproviders.ParseMultiSourceMatchingPatterns(methodConfig.Include)
		if err != nil {
			diags = diags.Append(tfdiags.Sourceless(
				tfdiags.Error,
				"Invalid provider source inclusion patterns",
				fmt.Sprintf("CLI config specifies invalid provider inclusion patterns: %s.", err),
			))
			continue
		}
		exclude, err := getproviders.ParseMultiSourceMatchingPatterns(methodConfig.Exclude)
		if err != nil {
			diags = diags.Append(tfdiags.Sourceless(
				tfdiags.Error,
				"Invalid provider source exclusion patterns",
				fmt.Sprintf("CLI config specifies invalid provider exclusion patterns: %s.", err),
			))
			continue
		}

		searchRules = append(searchRules, getproviders.MultiSourceSelector{
			Source:  source,
			Include: include,
			Exclude: exclude,
		})
	}

	return getproviders.MultiSource(searchRules), diags
}

func implicitProviderSource(
	ctx context.Context,
	registryClientConfig *cliconfig.RegistryProtocolsConfig,
	services *disco.Disco,
	searchRootDirs ...string,
) getproviders.Source {
	var searchRules []getproviders.MultiSourceSelector
	foundLocally := map[addrs.Provider]struct{}{}
	seenDirs := map[string]struct{}{}

	addLocalDir := func(dir string) {
		if dir == "" {
			return
		}
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
		if _, seen := seenDirs[dir]; seen {
			return
		}
		seenDirs[dir] = struct{}{}

		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			fsSource := getproviders.NewFilesystemMirrorSource(ctx, dir)
			if available, err := fsSource.AllAvailablePackages(); err == nil {
				for found := range available {
					foundLocally[found] = struct{}{}
				}
			}
			searchRules = append(searchRules, getproviders.MultiSourceSelector{
				Source: fsSource,
			})
		}
	}

	for _, rootDir := range searchRootDirs {
		if rootDir != "" {
			addLocalDir(filepath.Join(rootDir, "terraform.d/plugins"))
		}
	}

	if cliDataDirs, err := cliconfig.DataDirs(); err == nil {
		for _, cliDataDir := range cliDataDirs {
			addLocalDir(filepath.Join(cliDataDir, "plugins"))
		}
	}

	sysSpecificDirs := userdirs.ForApp("Terraform", "HashiCorp", "io.terraform")
	for _, dir := range sysSpecificDirs.DataSearchPaths("plugins") {
		addLocalDir(dir)
	}

	var directExcluded getproviders.MultiSourceMatchingPatterns
	for addr := range foundLocally {
		directExcluded = append(directExcluded, addr)
	}

	searchRules = append(searchRules, getproviders.MultiSourceSelector{
		Source: getproviders.NewMemoizeSource(
			getproviders.NewRegistrySource(ctx, services, newRegistryHTTPClient(ctx, registryClientConfig), providerSourceLocationConfigFromEnv()),
		),
		Exclude: directExcluded,
	})

	return getproviders.MultiSource(searchRules)
}

func providerSourceForCLIConfigLocation(
	ctx context.Context,
	loc cliconfig.ProviderInstallationLocation,
	locationRetries cliconfig.ProviderInstallationMethodRetries,
	trustedSource cliconfig.ProviderInstallationMethodTrusted,
	registryClientConfig *cliconfig.RegistryProtocolsConfig,
	services *disco.Disco,
	makeOCICredsPolicy oci.OCICredsPolicyBuilder,
) (getproviders.Source, tfdiags.Diagnostics) {
	if loc == cliconfig.ProviderInstallationDirect {
		return getproviders.NewMemoizeSource(
			getproviders.NewRegistrySource(ctx, services, newRegistryHTTPClient(ctx, registryClientConfig), providerSourceLocationConfig(locationRetries, trustedSource)),
		), nil
	}

	switch loc := loc.(type) {
	case cliconfig.ProviderInstallationFilesystemMirror:
		return getproviders.NewFilesystemMirrorSource(ctx, string(loc)), nil

	case cliconfig.ProviderInstallationNetworkMirror:
		u, err := url.Parse(string(loc))
		if err != nil {
			var diags tfdiags.Diagnostics
			diags = diags.Append(tfdiags.Sourceless(
				tfdiags.Error,
				"Invalid URL for provider installation source",
				fmt.Sprintf("Cannot parse %q as a URL for a network provider mirror: %s.", string(loc), err),
			))
			return nil, diags
		}
		if u.Scheme != "https" || u.Host == "" {
			var diags tfdiags.Diagnostics
			diags = diags.Append(tfdiags.Sourceless(
				tfdiags.Error,
				"Invalid URL for provider installation source",
				fmt.Sprintf("Cannot use %q as a URL for a network provider mirror: the mirror must be at an https: URL.", string(loc)),
			))
			return nil, diags
		}
		httpTimeout := newRegistryHTTPClient(ctx, registryClientConfig).HTTPClient.Timeout
		return getproviders.NewHTTPMirrorSource(ctx, u, services.CredentialsSource(), httpTimeout, providerSourceLocationConfig(locationRetries, trustedSource)), nil

	case cliconfig.ProviderInstallationOCIMirror:
		mappingFunc := loc.RepositoryMapping
		return getproviders.NewOCIRegistryMirrorSource(
			ctx,
			mappingFunc,
			func(ctx context.Context, registryDomain, repositoryName string) (getproviders.OCIRepositoryStore, error) {
				credsPolicy, err := makeOCICredsPolicy(ctx)
				if err != nil {
					return nil, fmt.Errorf("invalid credentials configuration for OCI registries: %w", err)
				}
				return oci.GetOCIRepositoryStore(ctx, registryDomain, repositoryName, credsPolicy)
			},
		), nil

	default:
		panic(fmt.Sprintf("unexpected provider source location type %T", loc))
	}
}

func providerDevOverrides(configs []*cliconfig.ProviderInstallation) map[addrs.Provider]getproviders.PackageLocalDir {
	if len(configs) == 0 {
		return nil
	}
	return configs[0].DevOverrides
}

func providerSourceLocationConfig(locationRetries cliconfig.ProviderInstallationMethodRetries, trustAllHashes cliconfig.ProviderInstallationMethodTrusted) getproviders.LocationConfig {
	var retries int
	var configured bool
	if locationRetries != nil {
		retries, configured = locationRetries()
	}
	if !configured {
		retries = cliconfig.ProviderDownloadRetries()
	}
	return getproviders.LocationConfig{
		ProviderDownloadRetries: retries,
		TrustAllHashes:          trustAllHashes != nil && trustAllHashes(),
	}
}

func providerSourceLocationConfigFromEnv() getproviders.LocationConfig {
	return getproviders.LocationConfig{
		ProviderDownloadRetries: cliconfig.ProviderDownloadRetries(),
	}
}

func parseReattachProviders(in string) (map[addrs.Provider]*plugin.ReattachConfig, error) {
	unmanagedProviders := map[addrs.Provider]*plugin.ReattachConfig{}
	if in != "" {
		type reattachConfig struct {
			Protocol        string
			ProtocolVersion int
			Addr            struct {
				Network string
				String  string
			}
			Pid  int
			Test bool
		}
		var m map[string]reattachConfig
		if err := json.Unmarshal([]byte(in), &m); err != nil {
			return unmanagedProviders, fmt.Errorf("Invalid format for TF_REATTACH_PROVIDERS: %w", err)
		}
		for p, c := range m {
			a, diags := addrs.ParseProviderSourceString(p)
			if diags.HasErrors() {
				return unmanagedProviders, fmt.Errorf("Error parsing %q as a provider address: %w", a, diags.Err())
			}
			var addr net.Addr
			var err error
			switch c.Addr.Network {
			case "unix":
				addr, err = net.ResolveUnixAddr("unix", c.Addr.String)
				if err != nil {
					return unmanagedProviders, fmt.Errorf("Invalid unix socket path %q for %q: %w", c.Addr.String, p, err)
				}
			case "tcp":
				addr, err = net.ResolveTCPAddr("tcp", c.Addr.String)
				if err != nil {
					return unmanagedProviders, fmt.Errorf("Invalid TCP address %q for %q: %w", c.Addr.String, p, err)
				}
			default:
				return unmanagedProviders, fmt.Errorf("Unknown address type %q for %q", c.Addr.Network, p)
			}
			unmanagedProviders[a] = &plugin.ReattachConfig{
				Protocol:        plugin.Protocol(c.Protocol),
				ProtocolVersion: c.ProtocolVersion,
				Pid:             c.Pid,
				Test:            c.Test,
				Addr:            addr,
			}
		}
	}
	return unmanagedProviders, nil
}

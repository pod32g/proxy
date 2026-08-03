package main

import (
	"sort"

	log "github.com/pod32g/simple-logger"
)

// deprecatedFlag is a flag that still works and should not be used.
//
// Nothing is removed here. A flag that vanishes between releases breaks a
// deployment at the worst moment — on the upgrade, before anything is serving —
// and the operator's only clue is a usage message. A flag that warns keeps
// working while telling them what to write instead.
type deprecatedFlag struct {
	// instead names the setting to use, in config-file terms.
	instead string
	// why explains what the replacement does better, when that is not obvious.
	why string
}

// deprecated is the whole list, and the only place a flag's status is recorded.
//
// Every entry has a config-file equivalent by construction:
// TestEveryFlagCanBeSetInTheConfigFile refuses a flag that does not, so nothing
// can be deprecated in favour of somewhere it cannot go.
var deprecated = map[string]deprecatedFlag{
	"policy-file": {
		instead: "policy: in the config file",
		why:     "the file holds the rules themselves rather than pointing at a second file",
	},
	"client-file": {
		instead: "clients: in the config file",
		why:     "the file holds the rules themselves rather than pointing at a second file",
	},
	"quota-file": {
		instead: "quotas: in the config file",
		why:     "the file holds the rules themselves rather than pointing at a second file",
	},
	"header": {
		instead: "header_rules: in the config file, or -header-rule",
		why:     "a conditional rule can express an unconditional one and more, and it is validated where it is written",
	},
}

// warnDeprecated reports every deprecated flag the operator actually set.
//
// Only what was set: listing what someone did not use would be noise on every
// start, and a warning nobody reads is the same as no warning. The check runs
// against the same explicit-settings record the precedence chain uses, so a
// value supplied through the environment counts too.
func warnDeprecated(logger *log.Logger, set overrides) {
	var used []string
	for name := range deprecated {
		if set.flags[name] || set.envs[envNameFor(name)] {
			used = append(used, name)
		}
	}
	sort.Strings(used)
	for _, name := range used {
		d := deprecated[name]
		logger.Warn("Deprecated flag; it still works and will be removed in a future release",
			log.String("flag", "-"+name),
			log.String("use_instead", d.instead),
			log.String("why", d.why))
	}
}

// envNameFor is the environment variable a flag also reads, for the few
// deprecated ones that have one. Kept beside the list rather than derived,
// because the naming is not perfectly regular and guessing it wrong would make
// the warning silently miss the environment route.
func envNameFor(flag string) string {
	switch flag {
	case "policy-file":
		return "PROXY_POLICY_FILE"
	case "client-file":
		return "PROXY_CLIENT_FILE"
	case "quota-file":
		return "PROXY_QUOTA_FILE"
	}
	return ""
}

package internal

import (
	"Bucket-Diver-Azure/models"
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/cloudflare/ahocorasick"
)

var (
	matcher      *ahocorasick.Matcher
	idToCategory []string
)

var (
	reHasUpper = regexp.MustCompile(`[A-Z]`)
	reHasLower = regexp.MustCompile(`[a-z]`)
	reHasDigit = regexp.MustCompile(`[0-9]`)
	reIsHex    = regexp.MustCompile(`^[a-fA-F0-9]+$`)
)

var keywords = map[string][]byte{
	"AWS_ACCESS_KEY":        []byte("akia"),
	"AWS_SECRET_KEY":        []byte("secret"),
	"STRIPE_KEY":            []byte("sk_live"),
	"GOOGLE_KEY":            []byte("aiza"),
	"DB_URL":                []byte("://"),
	"SLACK_WEBHOOK":         []byte("hooks.slack.com"),
	"SLACK_TOKEN":           []byte("xox"),
	"GITHUB_TOKEN":          []byte("gh"),
	"PRIVATE_KEY":           []byte("begin"),
	"JWT_SECRET":            []byte("eyj"),
	"AZURE_KEY":             []byte("accountkey="),
	"GCP_SERVICE_KEY":       []byte(`"private_key"`),
	"SENDGRID_KEY":          []byte("sg."),
	"TWILIO_KEY":            []byte("sk"),
	"NPM_TOKEN":             []byte("npm_"),
	"PYPI_TOKEN":            []byte("pypi-"),
	"TERRAFORM_CLOUD_TOKEN": []byte("atlasv1."),
	"DATADOG_API_KEY":       []byte("dd"),
}

var SecretPatterns = map[string]*regexp.Regexp{
	"AWS_ACCESS_KEY":        regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
	"AWS_SECRET_KEY":        regexp.MustCompile(`(?i)(?:secret|key|token|pass)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
	"STRIPE_KEY":            regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
	"GOOGLE_KEY":            regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
	"DB_URL":                regexp.MustCompile(`(postgres|mysql|mongodb(\+srv)?):\/\/[^:]+:[^@]+@[a-zA-Z0-9.\-]+(:[0-9]+)?(\/[^\s"']*)?`),
	"SLACK_WEBHOOK":         regexp.MustCompile(`https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+`),
	"SLACK_TOKEN":           regexp.MustCompile(`xox[bpoas]-[0-9A-Za-z\-]{10,}`),
	"GITHUB_TOKEN":          regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
	"PRIVATE_KEY":           regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
	"JWT_SECRET":            regexp.MustCompile(`ey[Jj][a-zA-Z0-9_-]+\.ey[Jj][a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
	"AZURE_KEY":             regexp.MustCompile(`(?i)AccountKey=[a-zA-Z0-9+/=]{88}`),
	"GCP_SERVICE_KEY":       regexp.MustCompile(`"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----`),
	"SENDGRID_KEY":          regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
	"TWILIO_KEY":            regexp.MustCompile(`\bSK[a-fA-F0-9]{32}\b`),
	"NPM_TOKEN":             regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
	"PYPI_TOKEN":            regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`),
	"TERRAFORM_CLOUD_TOKEN": regexp.MustCompile(`atlasv1\.[a-zA-Z0-9_\-]{24}`),
	"DATADOG_API_KEY":       regexp.MustCompile(`(?i)(dd_api_key|datadog.{0,20}key)\s*[:=]\s*["']?([a-f0-9]{32})["']?`),
}

var entropyCandidateRegex = regexp.MustCompile(`[A-Za-z0-9/\+=]{20,}`)

type SeenSecrets struct {
	mu     sync.Mutex
	filter *bloom.BloomFilter
}

func init() {
	categoryNames := make([]string, 0, len(keywords))
	for category := range keywords {
		categoryNames = append(categoryNames, category)
	}
	sort.Strings(categoryNames)

	words := make([][]byte, 0, len(categoryNames))
	for _, category := range categoryNames {
		words = append(words, keywords[category])
		idToCategory = append(idToCategory, category)
	}
	matcher = ahocorasick.NewMatcher(words)
}

func NewSeenSecrets() *SeenSecrets {
	return &SeenSecrets{filter: bloom.NewWithEstimates(1_000_000, 0.001)}
}

func (s *SeenSecrets) check(secret string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := []byte(secret)
	if s.filter.Test(b) {
		return true
	}
	s.filter.Add(b)
	return false
}

func ScanStream(ctx context.Context, bucket, filename, ext string, r io.Reader, seen *SeenSecrets, results chan<- models.Finding) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 5*1024*1024)

	entropyThreshold := 5.0
	skipEntropy := false

	switch ext {
	case ".env", ".tfvars", ".tfstate", ".ini", ".conf", ".properties", ".pem", ".key":
		entropyThreshold = 3.8
	case ".tf", ".hcl", ".yaml", ".yml", ".json", ".toml", ".xml", ".sql":
		entropyThreshold = 4.5
	case ".go", ".py", ".rb", ".java", ".php", ".rs", ".sh", ".bash", ".ps1":
		entropyThreshold = 5.5
	case ".js", ".ts", ".jsx", ".tsx", ".html", ".css", ".map", ".md", ".txt", ".log":
		skipEntropy = true
	default:
		entropyThreshold = 5.0
	}

	lineNumber := 0
	processedCategories := make(map[string]bool)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		lineNumber++
		lineBytes := scanner.Bytes()
		lineStr := string(lineBytes)
		lineLower := bytes.ToLower(lineBytes)

		hits := matcher.Match(lineLower)

		if len(hits) > 0 {
			for k := range processedCategories {
				delete(processedCategories, k)
			}
		} else if skipEntropy {
			continue
		}

		for _, id := range hits {
			category := idToCategory[id]

			if category == "PRIVATE_KEY" || category == "GCP_SERVICE_KEY" {
				var fullKey string
				startLine := lineNumber

				if strings.Contains(lineStr, "-----END") {
					if re, ok := SecretPatterns[category]; ok {
						if match := re.Find(lineBytes); match != nil {
							fullKey = string(match)
						}
					}
				}

				if fullKey == "" {
					var keyBlock strings.Builder
					keyBlock.WriteString(lineStr + "\n")
					foundEnd := false

					for scanner.Scan() {
						lineNumber++
						nextLine := scanner.Text()
						keyBlock.WriteString(nextLine + "\n")

						if strings.Contains(nextLine, "-----END") ||
							strings.Contains(nextLine, `\n"`) ||
							strings.Contains(nextLine, `",`) {
							foundEnd = true
							break
						}
						if lineNumber-startLine > 100 {
							break
						}
					}
					if foundEnd {
						fullKey = keyBlock.String()
					}
				}

				if fullKey != "" && !seen.check(fullKey) {
					results <- models.NewFinding(bucket, filename, startLine, fullKey, category)
				}
				continue
			}

			if processedCategories[category] {
				continue
			}
			processedCategories[category] = true

			if re, ok := SecretPatterns[category]; ok {
				for _, match := range re.FindAll(lineBytes, -1) {
					secret := string(match)
					if seen.check(secret) {
						continue
					}
					results <- models.NewFinding(bucket, filename, lineNumber, secret, category)
				}
			}
		}

		if skipEntropy {
			continue
		}

		for _, c := range entropyCandidateRegex.FindAll(lineBytes, -1) {
			candidateStr := string(c)

			if strings.ContainsAny(candidateStr, "/\\") {
				continue
			}

			if idx := strings.Index(string(lineBytes), candidateStr); idx > 0 {
				prev := lineBytes[idx-1]
				if (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') {
					continue
				}
			}

			lineContext := strings.ToLower(string(lineBytes))
			if !strings.Contains(lineContext, "=") && !strings.Contains(lineContext, ":") {
				continue
			}

			if len(candidateStr) < 32 || len(candidateStr) > 128 {
				continue
			}

			if !isLikelySecret(candidateStr) {
				continue
			}

			if calculateShannonEntropy(candidateStr) > entropyThreshold {
				if seen.check(candidateStr) {
					continue
				}
				results <- models.NewFinding(bucket, filename, lineNumber, candidateStr, "HIGH_ENTROPY_CANDIDATE")
			}
		}
	}

	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			slog.Warn("file skipped: line exceeds scanner buffer",
				"bucket", bucket,
				"file", filename,
			)
		} else {
			slog.Error("scan error",
				"bucket", bucket,
				"file", filename,
				"error", err,
			)
		}
	}
}

func ScanMetadata(bucket, filename string, metadata map[string]string, seen *SeenSecrets, findings chan<- models.Finding) {
	const metaEntropyThreshold = 4.0

	for k, v := range metadata {
		combined := k + "=" + v
		data := []byte(combined)

		for _, id := range matcher.Match(data) {
			category := idToCategory[id]
			if re, ok := SecretPatterns[category]; ok {
				if re.Match(data) {
					if seen.check(combined) {
						continue
					}
					findings <- models.NewFinding(bucket, filename+" (Metadata)", 0, combined, category)
				}
			}
		}

		if isLikelySecret(v) && calculateShannonEntropy(v) >= metaEntropyThreshold {
			if seen.check(v) {
				continue
			}
			findings <- models.NewFinding(bucket, filename+" (Metadata)", 0, v, "HIGH_ENTROPY_METADATA")
		}
	}
}

func calculateShannonEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]float64
	for i := 0; i < len(data); i++ {
		counts[data[i]]++
	}
	var entropy float64
	length := float64(len(data))
	for _, count := range counts {
		if count > 0 {
			p := count / length
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func isLikelySecret(s string) bool {
	l := len(s)
	if l < 20 || l > 128 {
		return false
	}

	upper := reHasUpper.MatchString(s)
	lower := reHasLower.MatchString(s)
	digit := reHasDigit.MatchString(s)

	if reIsHex.MatchString(s) {
		if !((upper && digit) || (lower && digit)) {
			return false
		}
	} else if !upper || !lower || !digit {
		return false
	}

	consecutive := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			consecutive++
			if consecutive > 5 {
				return false
			}
		} else {
			consecutive = 1
		}
	}
	return true
}

// This program converts goboringcrypto.h.in to the OpenSSL version.

package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"os"
	"os/exec"
	"bufio"
	"io"
)

const inputFile = "crypto/internal/boring/goboringcrypto.h.in"

// Translation from #include <openssl/X> headers to actual headers
// used by our OpenSSL version.
var opensslHeaderNames = map[string]string{
	"aead.h": "", // skip
	"aes.h": "aes.h",
	"bn.h": "bn.h",
	"crypto.h": "crypto.h",
	"digest.h": "evp.h", // duplicate
	"ec.h": "ec.h",
	"ec_key.h": "",
	"ecdsa.h": "ecdsa.h",
	"evp.h": "evp.h",
	"hmac.h": "hmac.h",
	"nid.h": "obj_mac.h",
	"rand.h": "rand.h",
	"rsa.h": "rsa.h",
	"sha.h": "sha.h",
}

// Functions which are not wrapped because they are unused and not
// available in OpenSSL.
var droppedFunctions = map[string]struct{}{
	"EC_KEY_is_opaque": {},
	"RSA_check_fips": {},
	"RSA_is_opaque": {},
	"RSA_private_key_from_bytes": {},
	"RSA_private_key_to_bytes": {},
	"RSA_public_key_from_bytes": {},
	"RSA_public_key_to_bytes": {},
	"RSA_encrypt": {},
	"RSA_decrypt": {},
}

// Functions which are not rewritten because they are incompatible
// with OpenSSL.
var unrewrittenFunctions = map[string]struct{}{
	// EVP_AED is not implemented in OpenSSL.  Need to use
	// EVP_CIPHER instead.
	"EVP_AEAD_CTX_cleanup": {},
	"EVP_AEAD_CTX_init": {},
	"EVP_AEAD_CTX_init_with_direction": {},
	"EVP_AEAD_CTX_open": {},
	"EVP_AEAD_CTX_seal": {},
	"EVP_AEAD_CTX_zero": {},
	"EVP_AEAD_key_length": {},
	"EVP_AEAD_max_overhead": {},
	"EVP_AEAD_max_tag_len": {},
	"EVP_AEAD_nonce_length": {},
	"EVP_aead_aes_128_gcm": {},
	"EVP_aead_aes_128_gcm_tls12": {},
	"EVP_aead_aes_256_gcm": {},
	"EVP_aead_aes_256_gcm_tls12": {},

	// These functions are emulated because the RSA structure is
	// non-opaque.
	"RSA_get0_crt_params": {},
	"RSA_get0_key": {},
	"RSA_get0_factors": {},

	// These functions need reimplementations.
	"RSA_sign_raw": {},
	"RSA_verify_raw": {},
	"RSA_sign_pss_mgf1": {},
	"RSA_verify_pss_mgf1": {},
	"RSA_generate_key_fips": {},

	// This is a new EVP method which needs backporting.
	"EVP_md5_sha1": {},

	// This is used as a hook for thread safety initialization of
	// OpenSSL.
	"BORINGSSL_bcm_power_on_self_test": {},

	// HMAC_CTX_copy with an already-initialized target.
	"HMAC_CTX_copy_ex": {},
}

// These functions are available under a different name.
var renamedFunctions = map[string]string{
	"EC_KEY_generate_key_fips": "EC_KEY_generate_key",
}

// These functions have arguments which lack const qualifiers in
// OpenSSL, so we need to cast them.  NB: Argument indices are 1-based
// (as in GCC).
var missingConstQualifiers = map[string][]int{
	"ECDSA_do_sign": {3},
	"ECDSA_do_verify": {4},
	"ECDSA_sign": {6},
	"ECDSA_verify": {6},
}

// These structs have different names in OpenSSL.
var renamedStructs = map[string]string{
	// OpenSSL uses the EVP_CIPHER interface for AEAD ciphers.
	// The functions dealing with them have been reimplemented.
	"EVP_AEAD": "EVP_CIPHER",
	"EVP_AEAD_CTX": "EVP_CIPHER_CTX",
}

// Type names, used for recognizing named parameters.
var typeNames = map[string]struct{}{
	"int": {},
	"size_t": {},
}

var rewriteIncludeRE = regexp.MustCompile(`^// #include <openssl/(\S+)>$`)
func rewriteInclude(line string, matches []string, wr *bufio.Writer) {
	header := matches[1]
	newHeader, found := opensslHeaderNames[header]
	if !found {
		log.Fatalf("error: unknown header file: <openssl/%s>\n",
			header)
	}
	if newHeader != "" {
		wr.WriteString("#include <openssl/")
		wr.WriteString(newHeader)
		wr.WriteString(">\n\n")
	}
}

var rewriteEnumRE = regexp.MustCompile(`^\tGO_(NID_\S+) = \d+,$`)
func rewriteEnum(line string, matches []string, wr *bufio.Writer) {
	id := matches[1]
	wr.WriteString("\tGO_")
	wr.WriteString(id)
	wr.WriteString(" = ")
	wr.WriteString(id)
	wr.WriteString(",\n")
}

var rewriteStructRE = regexp.MustCompile(
`^(?:/\*unchecked \(opaque\)\*/ )?typedef struct GO_(\S+) { char data\[\d+(?:\+\d+)?\]; } GO_(\S+);$`)
func rewriteStruct(line string, matches []string, wr *bufio.Writer) {
	wrappingName := matches[1]
	if wrappingName != matches[2] {
		log.Fatalf("error: mismatched struct identifiers: %#v\n", line)
	}

	wrappedName := wrappingName
	if otherName, found := renamedStructs[wrappingName]; found {
		wrappedName = otherName
	}
	
	wr.WriteString("typedef ")
	wr.WriteString(wrappedName)
	wr.WriteString(" GO_")
	wr.WriteString(wrappingName)
	wr.WriteString(";\n")
}

// Special case due to non-opaque definition.
var rewriteStructRSARE = regexp.MustCompile(`^typedef struct GO_RSA \{ `)
func rewriteStructRSA(line string, matches []string, wr *bufio.Writer) {
	wr.WriteString("typedef RSA GO_RSA;\n")
}

var rewriteFuncRE = regexp.MustCompile(
`^(?:/\*unchecked\*/ )?((?:[a-zA-Z0-9_]+(?:\s*\*)?\s+)+)_goboringcrypto_([a-zA-Z0-9_]+)\((.*)\);$`)
func rewriteFunc(line string, matches []string, wr *bufio.Writer) {
	returnType := matches[1]
	returnType = strings.Trim(returnType, " \t")
	wrappingName := matches[2]
	args := matches[3]

	if _, found := droppedFunctions[wrappingName]; found {
		return
	}
	if _, found := unrewrittenFunctions[wrappingName]; found {
		wr.WriteString(line)
		wr.WriteByte('\n')
		return
	}
	wrappedName := wrappingName
	if otherName, found := renamedFunctions[wrappingName]; found {
		wrappedName = otherName
	}

	wr.WriteString("static inline ")
	wr.WriteString(returnType)
	wr.WriteString("\n_goboringcrypto_")
	wr.WriteString(wrappingName)

	maybeWriteReturn := func() {
		if returnType != "void" {
			wr.WriteString("return ")
		}
	}

	var missingConsts []int
	if missing, found := missingConstQualifiers[wrappingName]; found {
		missingConsts = missing
	}
	maybeStripConst := func(i int, arg string) string {
		for _, argpos := range missingConsts {
			if i + 1 == argpos {
				if strings.HasPrefix(arg, "const ") {
					return arg[6:]
				}
				log.Fatalf("missing const prefix in argument %#v: %#v\n",
					arg, line)
			}
		}
		return arg
	}

	// Heuristic to extract the parameter name from an argument
	// string.
	paramName1 := func(arg string, delim byte) string {
		idx := strings.LastIndexByte(arg, delim)
		if idx >= 0 && idx != len(arg) - 1 {
			return strings.Trim(arg[idx + 1:], " \t")
		}
		return ""
	}
	paramName := func(arg string) (name string) {
		name = paramName1(arg, '*')
		if name != "" {
			return
		}
		if arg[len(arg) - 1] != '*' {
			name = paramName1(arg, ' ')
			if _, found := typeNames[name]; found {
				name = ""
			}
		}
		return
	}

	switch args {
	case "":
		log.Fatalf("function without arguments: %#v\n", line)
	case "void":
		wr.WriteString("(void)\n{\n\t")
		maybeWriteReturn()
		wr.WriteString(wrappedName)
		wr.WriteString("();\n}\n\n")
	default:
		wr.WriteString("(")
		argList := strings.Split(args, ",")
		for i, arg := range argList {
			arg = strings.Trim(arg, " \t")
			if i > 0 {
				wr.WriteString(", ")
			}
			if paramName(arg) == "" {
				_, err := fmt.Fprintf(wr, "%s arg%d", arg, i)
				if err != nil {
					panic(err)
				}
			} else {
				wr.WriteString(arg)
			}
		}
		wr.WriteString(")\n{\n\t")
		maybeWriteReturn()
		wr.WriteString(wrappedName)
		wr.WriteString("(")
		for i, arg := range argList {
			arg = strings.Trim(arg, " \t")
			if i > 0 {
				wr.WriteString(", ")
			}

			// Cast away const if necessary.
			strippedType := maybeStripConst(i, arg)
			if strippedType != arg {
				wr.WriteByte('(')
				wr.WriteString(strippedType)
				wr.WriteString(") ")
			}

			param := paramName(arg)
			if param == "" {
				_, err := fmt.Fprintf(wr, "arg%d", i)
				if err != nil {
					panic(err)
				}
			} else {
				wr.WriteString(param)
			}
		}
		wr.WriteString(");\n}\n\n")
	}
}

type rewriter struct {
	name string
	re *regexp.Regexp
	callback func(line string, args []string, wr *bufio.Writer)
}

var rewriters = []rewriter{
	{"include", rewriteIncludeRE, rewriteInclude},
	{"enum member", rewriteEnumRE, rewriteEnum},
	{"struct", rewriteStructRE, rewriteStruct},
	{"struct RSA", rewriteStructRSARE, rewriteStructRSA},
	{"function declaration", rewriteFuncRE, rewriteFunc},
}

// Exits with a non-zero status if fileName cannot be compiled as a C
// source file.
func checkCompile(fileName string) {
	cmd := exec.Command("gcc", "-x", "c", "-S", "-o-", "-Wall",
		// "-Werror=implicit-function-declaration",
		// "-Werror=implicit-int",
		"-Werror",
		fileName)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatalf("gcc invocation failed: %s\n", err)
	}
}

func main() {
	infile, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("could not open %#v: %s\n", inputFile, err)
	}
	defer infile.Close()

	outputFile := strings.TrimSuffix(inputFile, ".in")
	outputFileNew := outputFile + ".new"
	outfile, err := os.OpenFile(outputFileNew,
		os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("could not open %#v: %s\n", outputFileNew, err)
	}
	defer outfile.Close()
	wr := bufio.NewWriter(outfile)

	rd := bufio.NewReader(infile)
	counts := make([]int, len(rewriters))
	READ: for {
		line, err := rd.ReadString('\n')
		if line != "" {
			line = strings.TrimRight(line, "\n")
			for i, rewriter := range rewriters {
				matches := rewriter.re.FindStringSubmatch(line)
				if matches != nil {
					rewriter.callback(line, matches, wr)
					counts[i]++
					continue READ
				}
			}
			// Else output the original line.
			wr.WriteString(line)
			wr.WriteByte('\n')
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("error reading from %#v: %s", inputFile, err)
		}
	}
	for i, count := range counts {
		fmt.Fprintf(os.Stderr, "%s: %d\n", rewriters[i].name, count)
	}
	err = wr.Flush()
	if err != nil {
		log.Fatalf("error writing to %#v: %s", outputFileNew, err)
	}
	checkCompile(outputFileNew)
	err = os.Rename(outputFileNew, outputFile)
	if err != nil {
		log.Fatalf("cannot rename %#v to %#v: %s",
			outputFileNew, outputFile, err)
	}
}

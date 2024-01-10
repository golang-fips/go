package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func main() {
	// Script takes two arguments, the path to version.json,
	// and the name of the repository.
	if len(os.Args) < 3 {
		log.Fatal("Error: requires exactly two arguments")
	}
	versionFile := os.Args[1]
	repository := os.Args[2]

	// Read the mapping of repositories to git refs.
	content, err := os.ReadFile(versionFile)
	if err != nil {
		log.Fatal("Could not open file: ", err)
	}
	var gitRefs map[string]string
	err = json.Unmarshal(content, &gitRefs)
	if err != nil {
		log.Fatal("Could not unmarshal json: ", err)
	}

	// Print the result.
	if gitRef, ok := gitRefs[repository]; ok {
		fmt.Printf("%s\n", gitRef)
	} else {
		log.Fatalf("Invalid repository: %s", gitRef)
	}
}

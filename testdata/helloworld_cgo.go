// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package main

// use some cgo

/*
#include <stdio.h>
#include <stdlib.h>

void print_hello() {
	printf("Hello, World!\n");
}
*/
import "C"

func main() {
	C.print_hello()
}

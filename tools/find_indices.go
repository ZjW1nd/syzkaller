//go:build ignore

package main
import (
    "fmt"
    "os"
    "github.com/google/syzkaller/prog"
)
func main() {
    t, err := prog.GetTarget("windows", "amd64")
    if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
    for i, s := range t.Syscalls {
        fmt.Printf("%d %s\n", i, s.Name)
    }
}

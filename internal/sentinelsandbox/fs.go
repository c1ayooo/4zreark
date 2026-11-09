package sentinelsandbox

import "os"

// osWriteFile 单独包一层便于测试替换。
func osWriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

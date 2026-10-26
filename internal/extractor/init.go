package extractor

// init 注册内置提取器（按模板 id 分派）。新增提取器在此追加一行即可。
func init() {
	Register(sftpExtractor{})
	Register(phpinfoExtractor{})
	Register(gitExtractor{})
	Register(backupExtractor{})
}

package version

var (
	Version = "0.2.0"
	Commit  = ""
)

func String() string {
	if Commit != "" {
		return Version + " (" + Commit + ")"
	}
	return Version
}

// LessThan 比较两个版本串（形如 "0.2.0" 或 version.String() 的 "0.2.0 (abc)"）。
// 解析不出来的按 0.0.0 算——旧版 agent 不上报版本时天然过不了门槛。
func LessThan(a, b string) bool {
	return triple(a) < triple(b)
}

// triple 取 "x.y.z" 前三个数字，压成一个可比较的整数；解析失败返回 0。
func triple(s string) int {
	if i := indexByte(s, ' '); i >= 0 {
		s = s[:i] // 去掉 "(commit)" 尾巴
	}
	if i := indexByte(s, '-'); i >= 0 {
		s = s[:i] // 去掉 "-rc.1" 这类预发布尾巴，按基础版本比较
	}
	parts := [3]int{}
	var idx int
	num := -1
	for _, r := range s {
		if r >= '0' && r <= '9' {
			if num < 0 {
				num = 0
			}
			num = num*10 + int(r-'0')
			continue
		}
		if r == '.' {
			if num < 0 || idx >= 3 {
				return 0
			}
			parts[idx] = num
			idx++
			num = -1
			continue
		}
		return 0 // 出现别的字符：不是合法版本
	}
	if num < 0 || idx != 2 {
		return 0
	}
	parts[2] = num
	return parts[0]*1_000_000 + parts[1]*1_000 + parts[2]
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

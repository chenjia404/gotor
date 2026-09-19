package equix

import (
	"errors"
	"testing"
)

func TestVerifyOnly(t *testing.T) {
	eq, err := New([]byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	ok := Solution{0x2227, 0xa173, 0x365a, 0xb47d, 0x1bb2, 0xa077, 0x0d5e, 0xf25f}
	if err := eq.Verify(ok); err != nil {
		t.Fatalf("已知解应通过: %v", err)
	}
	badOrder := Solution{0x1bb2, 0xa077, 0x0d5e, 0xf25f, 0x2220, 0xa173, 0x365a, 0xb47d}
	if err := eq.Verify(badOrder); !errors.Is(err, ErrOrder) && err == nil {
		if checkTreeOrder(badOrder[:]) {
			t.Fatal("乱序解不应通过树序")
		}
	}
	badSum := Solution{0x2220, 0xa173, 0x365a, 0xb47d, 0x1bb2, 0xa077, 0x0d5e, 0xf25f}
	if err := eq.Verify(badSum); err == nil {
		t.Fatal("错误部分和应失败")
	}
}

func TestTorEquixVectors(t *testing.T) {
	mustFail := [][]byte{[]byte("bsipdp"), []byte("espceob")}
	for _, ch := range mustFail {
		if _, err := New(ch); err == nil {
			t.Fatalf("%q 应触发 ProgramConstraints", ch)
		}
	}

	cases := []struct {
		ch   string
		sols []Solution
	}{
		{"zzz", []Solution{{0xae21, 0xd392, 0x3215, 0xdd9c, 0x2f08, 0x93df, 0x232c, 0xe5dc}}},
		{"rrr", []Solution{{0x0873, 0x57a8, 0x73e0, 0x912e, 0x1ca8, 0xad96, 0x9abd, 0xd7de}}},
		{"qqq", []Solution{}},
		{"0123456789", []Solution{}},
		{"a", []Solution{
			{0x4b38, 0x8c81, 0x9255, 0xad99, 0x5ce7, 0xeb3e, 0xc635, 0xee38},
			{0x3f9e, 0x659b, 0x9ae6, 0xb891, 0x63ae, 0x777c, 0x06ca, 0xc593},
			{0x2227, 0xa173, 0x365a, 0xb47d, 0x1bb2, 0xa077, 0x0d5e, 0xf25f},
		}},
		{"abc", []Solution{
			{0x371f, 0x8865, 0x8189, 0xfbc3, 0x26df, 0xe4c0, 0xab39, 0xfe5a},
			{0x2101, 0xb88f, 0xc525, 0xccb3, 0x5785, 0xa41e, 0x4fba, 0xed18},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.ch, func(t *testing.T) {
			eq, err := New([]byte(tc.ch))
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range tc.sols {
				if err := eq.Verify(s); err != nil {
					t.Fatalf("已知解 Verify 失败: %v %v", s, err)
				}
			}
			found := eq.Solve()
			if len(tc.sols) == 0 && len(found) != 0 {
				t.Fatalf("期望无解，得到 %d", len(found))
			}
			want := map[Solution]struct{}{}
			for _, s := range tc.sols {
				want[s] = struct{}{}
			}
			got := map[Solution]struct{}{}
			for _, s := range found {
				got[s] = struct{}{}
				if err := eq.Verify(s); err != nil {
					t.Fatalf("求解结果无法验证: %v", err)
				}
			}
			for s := range want {
				if _, ok := got[s]; !ok {
					t.Fatalf("缺少已知解 %v（找到 %d 个）", s, len(found))
				}
			}
		})
	}
}

func TestEmptyChallenge(t *testing.T) {
	eq, err := New([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	known := []Solution{
		{0x0098, 0x3a4d, 0xc489, 0xcfba, 0x7ef3, 0xa498, 0xa00f, 0xec20},
		{0x78d8, 0x8611, 0xa4df, 0xec19, 0x0927, 0xa729, 0x842f, 0xf771},
		{0x54b5, 0xcc11, 0x1593, 0xe624, 0x9357, 0xb339, 0xb138, 0xed99},
	}
	for _, s := range known {
		if err := eq.Verify(s); err != nil {
			t.Fatalf("空挑战已知解失败: %v", err)
		}
	}
}

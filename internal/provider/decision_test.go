package provider

import "testing"

func TestPolicyBlocksOnlyAboveConfidence(t *testing.T) {
	t.Parallel()
	policy := Policy{MinConfidence: 0.6, CategoryMinProbability: 0.7}

	cases := []struct {
		name     string
		resp     *DecisionResponse
		want     bool
		wantConf float64
	}{
		{"clear block", &DecisionResponse{Block: true, Confidence: 0.93}, true, 0.93},
		{"weak block vote is dropped", &DecisionResponse{Block: true, Confidence: 0.55}, false, 0.55},
		{"clear allow", &DecisionResponse{Block: false, Confidence: 0.98}, false, 0.98},
		{
			name:     "category rescues a hesitating noul",
			resp:     &DecisionResponse{Block: true, Confidence: 0.587, Category: "analytics", CategoryProb: 0.9},
			want:     true,
			wantConf: 0.9,
		},
		{
			name:     "category below its own threshold does not rescue",
			resp:     &DecisionResponse{Block: true, Confidence: 0.587, Category: "analytics", CategoryProb: 0.65},
			want:     false,
			wantConf: 0.587,
		},
		{
			name:     "benign category never blocks",
			resp:     &DecisionResponse{Block: false, Confidence: 0.6, Category: "benign", CategoryProb: 0.95},
			want:     false,
			wantConf: 0.6,
		},
		{
			name:     "unknown category never blocks",
			resp:     &DecisionResponse{Block: false, Confidence: 0.55, Category: "unknown", CategoryProb: 0.99},
			want:     false,
			wantConf: 0.55,
		},
		{
			name:     "already blocked keeps noul confidence",
			resp:     &DecisionResponse{Block: true, Confidence: 0.92, Category: "ads", CategoryProb: 0.8},
			want:     true,
			wantConf: 0.92,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := policy.Decide(tc.resp)
			if got.Block != tc.want {
				t.Fatalf("block = %v, want %v (reason %q)", got.Block, tc.want, got.Reason)
			}
			if diff := got.Confidence - tc.wantConf; diff > 1e-9 || diff < -1e-9 {
				t.Fatalf("confidence = %v, want %v", got.Confidence, tc.wantConf)
			}
		})
	}
}

func TestPolicyNilResponse(t *testing.T) {
	t.Parallel()
	if got := (Policy{MinConfidence: 0.6}).Decide(nil); got.Block {
		t.Fatal("nil response must not block")
	}
}

func TestPolicyDefaultsFromZeroValue(t *testing.T) {
	t.Parallel()
	// Zero thresholds must not turn into "block everything".
	got := (Policy{}).Decide(&DecisionResponse{Block: false, Confidence: 0.9, Category: "benign", CategoryProb: 0.9})
	if got.Block {
		t.Fatal("zero-value policy blocked a benign verdict")
	}
}

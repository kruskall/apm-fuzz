package fuzz

type Option func(*config)

type config struct {
	maxDepth              int
	allowUnexportedFields bool
	nilChance             float64
}

func defaultConfig() *config {
	return &config{
		maxDepth:              5,
		allowUnexportedFields: false,
		nilChance:             0.5,
	}
}

func WithMaxDepth(i int) Option {
	return func(c *config) {
		c.maxDepth = i
	}
}

func WithUnexportedFields(b bool) Option {
	return func(c *config) {
		c.allowUnexportedFields = b
	}
}

func WithNilChance(p float64) Option {
	return func(c *config) {
		c.nilChance = p
	}
}

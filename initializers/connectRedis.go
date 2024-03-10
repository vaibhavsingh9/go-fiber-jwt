package initializers

import (
	"fmt"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/context"
)

var (
	RedisClient *redis.Client
	ctx         context.Context
)

func ConnectRedis(config *Config) {
	ctx = context.Background()

	RedisClient = redis.NewClient(&redis.Options{
		Addr: config.RedisUri,
	})
	//sending a ping command in Redis terminal to check whether connection is alive or not
	if _, err := RedisClient.Ping(ctx).Result(); err != nil {
		panic(err)
	}
	err := RedisClient.Set(ctx, "test (key)", "test (value)", 0).Err()
	if err != nil {
		panic(err)
	}
	fmt.Println("Redis client connected successfully..")
}

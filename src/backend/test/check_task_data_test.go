package test

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestCheckSpecificTask(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://root:fmdbw68b@dbconn.sealoshzh.site:32516/?directConnection=true"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	db := client.Database("4zreark")
	collection := db.Collection("scan_results")

	// 获取最新的任务（按创建时间排序）
	fmt.Println("=== Finding Latest Task ===")
	var latestTask bson.M
	taskCursor, err := collection.Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(1))
	if err != nil {
		log.Fatal(err)
	}
	if taskCursor.Next(ctx) {
		taskCursor.Decode(&latestTask)
		taskID := latestTask["task_id"].(primitive.ObjectID)
		fmt.Printf("Latest Task ID: %s\n", taskID.Hex())
		fmt.Printf("Created At: %v\n\n", latestTask["created_at"])

		// 1. 查看该任务的 subdomain 数据
		fmt.Println("=== Subdomain Data for this Task ===")
		subFilter := bson.M{
			"task_id": taskID,
			"type":    "subdomain",
		}
		subCursor, _ := collection.Find(ctx, subFilter, options.Find().SetLimit(5))
		subCount := 0
		for subCursor.Next(ctx) {
			var result bson.M
			subCursor.Decode(&result)
			data := result["data"].(bson.M)
			subCount++
			fmt.Printf("#%d subdomain: %v, domain: %v\n", subCount, data["subdomain"], data["domain"])
		}
		totalSub, _ := collection.CountDocuments(ctx, subFilter)
		fmt.Printf("Total subdomains: %d\n\n", totalSub)

		// 2. 查看该任务的 service 数据
		fmt.Println("=== Service Data for this Task ===")
		svcFilter := bson.M{
			"task_id": taskID,
			"type":    "service",
		}
		svcCursor, _ := collection.Find(ctx, svcFilter, options.Find().SetLimit(5))
		svcCount := 0
		for svcCursor.Next(ctx) {
			var result bson.M
			svcCursor.Decode(&result)
			data := result["data"].(bson.M)
			svcCount++
			fmt.Printf("#%d host: %v, title: %v, status: %v, url: %v\n",
				svcCount, data["host"], data["title"], data["status_code"], data["url"])
		}
		totalSvc, _ := collection.CountDocuments(ctx, svcFilter)
		fmt.Printf("Total services: %d\n\n", totalSvc)

		// 3. 尝试匹配
		fmt.Println("=== Matching Test ===")
		serviceMap := make(map[string]bson.M)
		svcCursor2, _ := collection.Find(ctx, svcFilter)
		for svcCursor2.Next(ctx) {
			var result bson.M
			svcCursor2.Decode(&result)
			data := result["data"].(bson.M)
			if host, ok := data["host"].(string); ok && host != "" {
				if _, exists := serviceMap[host]; !exists {
					serviceMap[host] = data
				}
			}
		}
		fmt.Printf("serviceMap has %d entries\n", len(serviceMap))
		fmt.Println("Sample serviceMap keys:")
		count := 0
		for k := range serviceMap {
			fmt.Printf("  - %s\n", k)
			count++
			if count >= 5 {
				break
			}
		}

		// 检查匹配情况
		fmt.Println("\nMatching subdomains with services:")
		subCursor2, _ := collection.Find(ctx, subFilter, options.Find().SetLimit(10))
		matched := 0
		notMatched := 0
		for subCursor2.Next(ctx) {
			var result bson.M
			subCursor2.Decode(&result)
			data := result["data"].(bson.M)

			// 先尝试 subdomain 字段
			subdomain := ""
			if s, ok := data["subdomain"].(string); ok && s != "" {
				subdomain = s
			} else if d, ok := data["domain"].(string); ok && d != "" {
				subdomain = d
			}

			if subdomain != "" {
				if svcData, exists := serviceMap[subdomain]; exists {
					matched++
					fmt.Printf("✓ MATCH: %s -> title=%v, status=%v\n",
						subdomain, svcData["title"], svcData["status_code"])
				} else {
					notMatched++
					fmt.Printf("✗ NO MATCH: %s\n", subdomain)
				}
			}
		}
		fmt.Printf("\nMatched: %d, Not Matched: %d\n", matched, notMatched)
	}
}

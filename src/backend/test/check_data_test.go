package test

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestCheckData(t *testing.T) {
	// 连接 MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://root:fmdbw68b@dbconn.sealoshzh.site:32516/?directConnection=true"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	db := client.Database("4zreark")
	collection := db.Collection("scan_results")

	// 1. 查看 subdomain 数据的格式
	fmt.Println("=== Subdomain Data (first 3) ===")
	subCursor, err := collection.Find(ctx, bson.M{"type": "subdomain"}, options.Find().SetLimit(3))
	if err != nil {
		log.Fatal(err)
	}
	for subCursor.Next(ctx) {
		var result bson.M
		subCursor.Decode(&result)
		data := result["data"].(bson.M)
		fmt.Printf("subdomain field: %v\n", data["subdomain"])
		fmt.Printf("domain field: %v\n", data["domain"])
		fmt.Printf("Full data: %+v\n\n", data)
	}

	// 2. 查看 service 数据的格式
	fmt.Println("\n=== Service Data (first 3) ===")
	svcCursor, err := collection.Find(ctx, bson.M{"type": "service"}, options.Find().SetLimit(3))
	if err != nil {
		log.Fatal(err)
	}
	for svcCursor.Next(ctx) {
		var result bson.M
		svcCursor.Decode(&result)
		data := result["data"].(bson.M)
		fmt.Printf("host field: %v\n", data["host"])
		fmt.Printf("url field: %v\n", data["url"])
		fmt.Printf("title field: %v\n", data["title"])
		fmt.Printf("status_code field: %v\n", data["status_code"])
		fmt.Printf("Full data: %+v\n\n", data)
	}

	// 3. 统计各类型数量
	fmt.Println("\n=== Result Type Counts ===")
	pipeline := []bson.M{
		{"$group": bson.M{
			"_id":   "$type",
			"count": bson.M{"$sum": 1},
		}},
	}
	aggCursor, _ := collection.Aggregate(ctx, pipeline)
	for aggCursor.Next(ctx) {
		var result bson.M
		aggCursor.Decode(&result)
		fmt.Printf("Type: %v, Count: %v\n", result["_id"], result["count"])
	}
}

func TestMatchingData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://root:fmdbw68b@dbconn.sealoshzh.site:32516/?directConnection=true"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	db := client.Database("4zreark")
	collection := db.Collection("scan_results")

	// 1. 构建 service host 到数据的映射
	fmt.Println("=== Building Service Map ===")
	serviceMap := make(map[string]bson.M)
	svcCursor, _ := collection.Find(ctx, bson.M{"type": "service"})
	for svcCursor.Next(ctx) {
		var result bson.M
		svcCursor.Decode(&result)
		data := result["data"].(bson.M)
		if host, ok := data["host"].(string); ok && host != "" {
			if _, exists := serviceMap[host]; !exists {
				serviceMap[host] = data
			}
		}
	}
	fmt.Printf("ServiceMap has %d entries\n", len(serviceMap))

	// 打印所有 service hosts
	fmt.Println("\nService hosts:")
	for host := range serviceMap {
		fmt.Printf("  - %s\n", host)
	}

	// 2. 检查 subdomain 数据能否匹配
	fmt.Println("\n=== Checking Subdomain Matching ===")
	subCursor, _ := collection.Find(ctx, bson.M{"type": "subdomain"}, options.Find().SetLimit(20))
	matchCount := 0
	noMatchCount := 0
	for subCursor.Next(ctx) {
		var result bson.M
		subCursor.Decode(&result)
		data := result["data"].(bson.M)

		domainName := ""
		if d, ok := data["domain"].(string); ok && d != "" {
			domainName = d
		} else if s, ok := data["subdomain"].(string); ok && s != "" {
			domainName = s
		}

		if domainName != "" {
			if serviceInfo, exists := serviceMap[domainName]; exists {
				matchCount++
				fmt.Printf("✓ MATCH: %s -> title=%v, status=%v\n", domainName, serviceInfo["title"], serviceInfo["status_code"])
			} else {
				noMatchCount++
				fmt.Printf("✗ NO MATCH: %s\n", domainName)
			}
		}
	}
	fmt.Printf("\nTotal: %d matches, %d no matches\n", matchCount, noMatchCount)
}

func TestTaskSpecificData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://root:fmdbw68b@dbconn.sealoshzh.site:32516/?directConnection=true"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	db := client.Database("4zreark")
	collection := db.Collection("scan_results")

	// 查找最近的任务
	fmt.Println("=== Recent Tasks with Results ===")
	taskPipeline := []bson.M{
		{"$group": bson.M{
			"_id":   "$task_id",
			"count": bson.M{"$sum": 1},
			"types": bson.M{"$addToSet": "$type"},
		}},
		{"$sort": bson.M{"_id": -1}},
		{"$limit": 5},
	}
	taskCursor, _ := collection.Aggregate(ctx, taskPipeline)
	var taskIDs []interface{}
	for taskCursor.Next(ctx) {
		var result bson.M
		taskCursor.Decode(&result)
		fmt.Printf("Task ID: %v, Count: %v, Types: %v\n", result["_id"], result["count"], result["types"])
		taskIDs = append(taskIDs, result["_id"])
	}

	if len(taskIDs) > 0 {
		// 检查第一个任务的子域名和服务数据
		taskID := taskIDs[0]
		fmt.Printf("\n=== Task %v Details ===\n", taskID)

		// 子域名数量
		subCount, _ := collection.CountDocuments(ctx, bson.M{"task_id": taskID, "type": "subdomain"})
		fmt.Printf("Subdomains: %d\n", subCount)

		// 服务数量
		svcCount, _ := collection.CountDocuments(ctx, bson.M{"task_id": taskID, "type": "service"})
		fmt.Printf("Services: %d\n", svcCount)

		// 显示该任务的服务数据
		fmt.Println("\nServices in this task:")
		svcCursor, _ := collection.Find(ctx, bson.M{"task_id": taskID, "type": "service"}, options.Find().SetLimit(5))
		for svcCursor.Next(ctx) {
			var result bson.M
			svcCursor.Decode(&result)
			data := result["data"].(bson.M)
			fmt.Printf("  Host: %v, Title: %v, Status: %v\n", data["host"], data["title"], data["status_code"])
		}

		// 显示该任务的子域名数据
		fmt.Println("\nSubdomains in this task:")
		subCursor, _ := collection.Find(ctx, bson.M{"task_id": taskID, "type": "subdomain"}, options.Find().SetLimit(5))
		for subCursor.Next(ctx) {
			var result bson.M
			subCursor.Decode(&result)
			data := result["data"].(bson.M)
			fmt.Printf("  Domain: %v, IPs: %v\n", data["domain"], data["ips"])
		}
	}
}

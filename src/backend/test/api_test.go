package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestGetSubdomainResultsAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://root:fmdbw68b@dbconn.sealoshzh.site:32516/?directConnection=true"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect(ctx)

	db := client.Database("4zreark")
	collection := db.Collection("scan_results")

	// 获取最新的任务ID
	var latestTask bson.M
	taskCursor, _ := collection.Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(1))
	if taskCursor.Next(ctx) {
		taskCursor.Decode(&latestTask)
		taskID := latestTask["task_id"].(primitive.ObjectID)

		fmt.Printf("Testing GetSubdomainResults logic for task: %s\n\n", taskID.Hex())

		// 模拟 GetSubdomainResults 的逻辑
		// 1. 构建 serviceMap
		serviceFilter := bson.M{
			"task_id": taskID,
			"type":    "service",
		}
		serviceCursor, _ := collection.Find(ctx, serviceFilter)

		serviceMap := make(map[string]map[string]interface{})
		for serviceCursor.Next(ctx) {
			var result bson.M
			serviceCursor.Decode(&result)
			data := result["data"].(bson.M)
			if host, ok := data["host"].(string); ok && host != "" {
				if _, exists := serviceMap[host]; !exists {
					// 转换为 map[string]interface{}
					dataMap := make(map[string]interface{})
					for k, v := range data {
						dataMap[k] = v
					}
					serviceMap[host] = dataMap
				}
			}
		}
		fmt.Printf("serviceMap has %d entries\n\n", len(serviceMap))

		// 2. 查询子域名并合并数据
		subFilter := bson.M{
			"task_id": taskID,
			"type":    "subdomain",
		}
		subCursor, _ := collection.Find(ctx, subFilter, options.Find().SetLimit(5))

		fmt.Println("=== Subdomain Results with Service Data ===")
		for subCursor.Next(ctx) {
			var result bson.M
			subCursor.Decode(&result)
			data := result["data"].(bson.M)

			// 构建结果 item
			item := make(map[string]interface{})
			for k, v := range data {
				item[k] = v
			}

			// 尝试匹配 service 数据
			// 先尝试 subdomain 字段
			domainName := ""
			if s, ok := data["subdomain"].(string); ok && s != "" {
				domainName = s
			} else if d, ok := data["domain"].(string); ok && d != "" {
				domainName = d
			}

			matched := false
			if domainName != "" {
				if serviceInfo, exists := serviceMap[domainName]; exists {
					matched = true
					// 补充数据
					if title, ok := serviceInfo["title"].(string); ok && title != "" {
						item["title"] = title
					}
					if statusCode, ok := serviceInfo["status_code"].(int32); ok {
						item["status_code"] = int(statusCode)
					} else if statusCode, ok := serviceInfo["status_code"].(int); ok {
						item["status_code"] = statusCode
					}
					if server, ok := serviceInfo["server"].(string); ok && server != "" {
						item["web_server"] = server
					}
					if url, ok := serviceInfo["url"].(string); ok && url != "" {
						item["url"] = url
					}
				}
			}

			// 打印结果
			if matched {
				fmt.Printf("✓ %s -> title=%v, status=%v, server=%v\n",
					domainName, item["title"], item["status_code"], item["web_server"])
			} else {
				fmt.Printf("✗ %s -> NO MATCH\n", domainName)
			}
		}
	}
}

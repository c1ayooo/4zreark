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

func TestLatestTaskData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://root:fmdbw68b@dbconn.sealoshzh.site:32516/?directConnection=true"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	db := client.Database("4zreark")
	collection := db.Collection("scan_results")

	// 找到最新的任务 ID
	taskID, _ := primitive.ObjectIDFromHex("69324abd37fbc53489eceaf6")

	fmt.Println("=== Subdomain Data Details ===")
	subCursor, _ := collection.Find(ctx, bson.M{"task_id": taskID, "type": "subdomain"}, options.Find().SetLimit(10))
	for subCursor.Next(ctx) {
		var result bson.M
		subCursor.Decode(&result)
		data := result["data"].(bson.M)
		fmt.Printf("subdomain: %v\n", data["subdomain"])
		fmt.Printf("domain: %v\n", data["domain"])
		fmt.Printf("root_domain: %v\n", data["root_domain"])
		fmt.Printf("ips: %v\n", data["ips"])
		fmt.Println("---")
	}
}

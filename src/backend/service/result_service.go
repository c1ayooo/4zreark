package service

import (
	"context"
	"github.com/c1ayooo/4zreark/database"
	"github.com/c1ayooo/4zreark/models"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ResultService struct {
	collection *mongo.Collection
}

func NewResultService() *ResultService {
	return &ResultService{
		collection: database.GetCollection(models.CollectionScanResults),
	}
}

// normalizeServiceURL 标准化 URL，移除默认端口（用于 Service 去重）
func normalizeServiceURL(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}

	// 移除 :443 (HTTPS 默认端口)
	if len(rawURL) > 4 {
		rawURL = strings.Replace(rawURL, ":443/", "/", 1)
		if strings.HasSuffix(rawURL, ":443") {
			rawURL = rawURL[:len(rawURL)-4]
		}
	}

	// 移除 :80 (HTTP 默认端口)
	if len(rawURL) > 3 {
		rawURL = strings.Replace(rawURL, ":80/", "/", 1)
		if strings.HasSuffix(rawURL, ":80") {
			rawURL = rawURL[:len(rawURL)-3]
		}
	}

	return rawURL
}

// extractHostFromURL 从 URL 中提取 host（用于 Web 服务按 host 去重）
func extractHostFromURL(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}

	// 移除协议前缀
	host := rawURL
	if strings.HasPrefix(host, "https://") {
		host = host[8:]
	} else if strings.HasPrefix(host, "http://") {
		host = host[7:]
	}

	// 移除路径
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	// 移除默认端口
	if strings.HasSuffix(host, ":443") {
		host = host[:len(host)-4]
	} else if strings.HasSuffix(host, ":80") {
		host = host[:len(host)-3]
	}

	return host
}

// CreateResult 创建扫描结果
func (s *ResultService) CreateResult(result *models.ScanResult) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	result.CreatedAt = time.Now()
	result.UpdatedAt = time.Now()

	res, err := s.collection.InsertOne(ctx, result)
	if err != nil {
		return err
	}

	result.ID = res.InsertedID.(primitive.ObjectID)
	return nil
}

// CreateResultWithDedup 创建扫描结果（带去重）
// 根据 type 和 data 中的关键字段进行去重
func (s *ResultService) CreateResultWithDedup(result *models.ScanResult) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	// 构建去重过滤条件
	filter := bson.M{
		"task_id": result.TaskID,
		"type":    result.Type,
	}

	// 根据不同类型添加特定的去重字段
	switch result.Type {
	case models.ResultTypeSubdomain:
		if subdomain, ok := result.Data["subdomain"].(string); ok && subdomain != "" {
			filter["data.subdomain"] = subdomain
		}
	case models.ResultTypePort:
		if ip, ok := result.Data["ip"].(string); ok && ip != "" {
			filter["data.ip"] = ip
		}
		if port, ok := result.Data["port"]; ok {
			filter["data.port"] = port
		}
	case models.ResultTypeService:
		// Web服务按 host 去重（同一个 host 的 http 和 https 只保留一条）
		if rawURL, ok := result.Data["url"].(string); ok && rawURL != "" {
			host := extractHostFromURL(rawURL)
			filter["data.dedup_host"] = host
			// 存储用于去重的 host
			result.Data["dedup_host"] = host
			// 同时存储标准化后的 URL
			result.Data["normalized_url"] = normalizeServiceURL(rawURL)
		}
	case models.ResultTypeURL, models.ResultTypeCrawler:
		if rawURL, ok := result.Data["url"].(string); ok && rawURL != "" {
			normalizedURL := normalizeServiceURL(rawURL)
			filter["data.normalized_url"] = normalizedURL
			result.Data["normalized_url"] = normalizedURL
		}
	case models.ResultTypeDirScan:
		if rawURL, ok := result.Data["url"].(string); ok && rawURL != "" {
			normalizedURL := normalizeServiceURL(rawURL)
			filter["data.normalized_url"] = normalizedURL
			result.Data["normalized_url"] = normalizedURL
		}
	case models.ResultTypeVuln:
		if vulnID, ok := result.Data["vuln_id"].(string); ok && vulnID != "" {
			filter["data.vuln_id"] = vulnID
		}
		if target, ok := result.Data["target"].(string); ok && target != "" {
			filter["data.target"] = target
		}
	case models.ResultTypeSensitive:
		if url, ok := result.Data["url"].(string); ok && url != "" {
			filter["data.url"] = url
		}
		if matchType, ok := result.Data["type"].(string); ok && matchType != "" {
			filter["data.type"] = matchType
		}
	}

	// 使用 Upsert：存在则更新，不存在则插入
	result.UpdatedAt = time.Now()

	update := bson.M{
		"$set": bson.M{
			"data":       result.Data,
			"source":     result.Source,
			"tags":       result.Tags,
			"project":    result.Project,
			"updated_at": result.UpdatedAt,
		},
		"$setOnInsert": bson.M{
			"task_id":      result.TaskID,
			"workspace_id": result.WorkspaceID,
			"type":         result.Type,
			"created_at":   time.Now(),
		},
	}

	opts := options.Update().SetUpsert(true)
	_, err := s.collection.UpdateOne(ctx, filter, update, opts)
	return err
}

// BatchCreateResults 批量创建扫描结果
func (s *ResultService) BatchCreateResults(results []models.ScanResult) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	docs := make([]interface{}, len(results))
	now := time.Now()
	for i := range results {
		results[i].CreatedAt = now
		results[i].UpdatedAt = now
		docs[i] = results[i]
	}

	_, err := s.collection.InsertMany(ctx, docs)
	return err
}

// BatchCreateResultsWithDedup 批量创建扫描结果（带去重）
func (s *ResultService) BatchCreateResultsWithDedup(results []models.ScanResult) (int, int, error) {
	inserted := 0
	skipped := 0

	for i := range results {
		err := s.CreateResultWithDedup(&results[i])
		if err != nil {
			skipped++
		} else {
			inserted++
		}
	}

	return inserted, skipped, nil
}

// GetResultsByTask 获取任务的扫描结果
func (s *ResultService) GetResultsByTask(taskID string, resultType models.ResultType, page, pageSize int, search string, statusCode int) ([]models.ScanResult, int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, 0, err
	}

	filter := bson.M{"task_id": objID}
	if resultType != "" {
		filter["type"] = resultType
	}

	// 状态码筛选（主要用于目录扫描结果）
	if statusCode > 0 {
		filter["data.status"] = statusCode
	}

	if search != "" {
		// 根据不同类型搜索不同字段
		filter["$or"] = []bson.M{
			{"data.domain": bson.M{"$regex": search, "$options": "i"}},
			{"data.subdomain": bson.M{"$regex": search, "$options": "i"}},
			{"data.url": bson.M{"$regex": search, "$options": "i"}},
			{"data.ip": bson.M{"$regex": search, "$options": "i"}},
			{"data.company": bson.M{"$regex": search, "$options": "i"}},
			{"project": bson.M{"$regex": search, "$options": "i"}},
		}
	}

	// 计算总数
	total, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	skip := int64((page - 1) * pageSize)
	opts := options.Find().
		SetSkip(skip).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var results []models.ScanResult
	if err = cursor.All(ctx, &results); err != nil {
		return nil, 0, err
	}

	return results, total, nil
}

// GetResultStats 获取任务结果统计
func (s *ResultService) GetResultStats(taskID string) (map[string]int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, err
	}

	pipeline := []bson.M{
		{"$match": bson.M{"task_id": objID}},
		{"$group": bson.M{
			"_id":   "$type",
			"count": bson.M{"$sum": 1},
		}},
	}

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	stats := make(map[string]int64)
	for cursor.Next(ctx) {
		var result struct {
			ID    string `bson:"_id"`
			Count int64  `bson:"count"`
		}
		if err := cursor.Decode(&result); err != nil {
			continue
		}
		stats[result.ID] = result.Count
	}

	return stats, nil
}

// DeleteResultsByTask 删除任务的所有结果
func (s *ResultService) DeleteResultsByTask(taskID string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return err
	}

	_, err = s.collection.DeleteMany(ctx, bson.M{"task_id": objID})
	return err
}

// UpdateResultTags 更新结果标签
func (s *ResultService) UpdateResultTags(id string, tags []string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	update := bson.M{
		"$set": bson.M{
			"tags":       tags,
			"updated_at": time.Now(),
		},
	}

	_, err = s.collection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	return err
}

// AddResultTag 添加标签
func (s *ResultService) AddResultTag(id string, tag string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	update := bson.M{
		"$addToSet": bson.M{"tags": tag},
		"$set":      bson.M{"updated_at": time.Now()},
	}

	_, err = s.collection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	return err
}

// RemoveResultTag 移除标签
func (s *ResultService) RemoveResultTag(id string, tag string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	update := bson.M{
		"$pull": bson.M{"tags": tag},
		"$set":  bson.M{"updated_at": time.Now()},
	}

	_, err = s.collection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	return err
}

// ExportResults 导出结果 (返回所有匹配的结果，不分页)
func (s *ResultService) ExportResults(taskID string, resultType models.ResultType) ([]models.ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"task_id": objID}
	if resultType != "" {
		filter["type"] = resultType
	}

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []models.ScanResult
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}

// UpdateSubdomainCDN 更新子域名的 CDN 信息
func (s *ResultService) UpdateSubdomainCDN(taskID string, domain string, cdnProvider string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return err
	}

	// 尝试匹配 subdomain 字段或 domain 字段
	filter := bson.M{
		"task_id": objID,
		"type":    models.ResultTypeSubdomain,
		"$or": []bson.M{
			{"data.subdomain": domain},
			{"data.domain": domain},
		},
	}

	update := bson.M{
		"$set": bson.M{
			"data.cdn":          true,
			"data.cdn_provider": cdnProvider,
			"updated_at":        time.Now(),
		},
	}

	_, err = s.collection.UpdateMany(ctx, filter, update)
	return err
}

// BatchDeleteResults 批量删除结果
func (s *ResultService) BatchDeleteResults(ids []string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objIDs := make([]primitive.ObjectID, 0, len(ids))
	for _, id := range ids {
		objID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			continue
		}
		objIDs = append(objIDs, objID)
	}

	if len(objIDs) == 0 {
		return nil
	}

	_, err := s.collection.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": objIDs}})
	return err
}

// GetSubdomainResults 获取子域名结果 (带解析，联合查询 service 数据补充指纹信息)
func (s *ResultService) GetSubdomainResults(taskID string, page, pageSize int, search string) ([]map[string]interface{}, int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, 0, err
	}

	// 1. 先查询所有 service 类型结果，用于后续关联
	serviceFilter := bson.M{
		"task_id": objID,
		"type":    models.ResultTypeService,
	}
	serviceCursor, err := s.collection.Find(ctx, serviceFilter)
	if err != nil {
		return nil, 0, err
	}
	defer serviceCursor.Close(ctx)

	// 构建 host -> service 信息的映射
	serviceMap := make(map[string]map[string]interface{})
	for serviceCursor.Next(ctx) {
		var result models.ScanResult
		if err := serviceCursor.Decode(&result); err != nil {
			continue
		}
		if host, ok := result.Data["host"].(string); ok && host != "" {
			// 使用第一个匹配的 service 信息（通常是 443 或 80 端口）
			if _, exists := serviceMap[host]; !exists {
				serviceMap[host] = result.Data
			}
		}
	}

	// 2. 查询子域名结果
	filter := bson.M{
		"task_id": objID,
		"type":    models.ResultTypeSubdomain,
	}
	if search != "" {
		filter["$or"] = []bson.M{
			{"data.subdomain": bson.M{"$regex": search, "$options": "i"}},
			{"data.domain": bson.M{"$regex": search, "$options": "i"}},
			{"data.title": bson.M{"$regex": search, "$options": "i"}},
		}
	}

	total, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	skip := int64((page - 1) * pageSize)
	opts := options.Find().
		SetSkip(skip).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	for cursor.Next(ctx) {
		var result models.ScanResult
		if err := cursor.Decode(&result); err != nil {
			continue
		}

		item := map[string]interface{}{
			"id":         result.ID.Hex(),
			"task_id":    result.TaskID.Hex(),
			"type":       result.Type,
			"tags":       result.Tags,
			"project":    result.Project,
			"created_at": result.CreatedAt,
		}

		// 解析 data 字段 (Data 已经是 bson.M 类型)
		for k, v := range result.Data {
			item[k] = v
		}

		// 3. 尝试从 service 结果中补充 title, status_code, fingerprint 等信息
		// 优先使用 subdomain 字段（完整子域名），因为 service 的 host 也是完整子域名
		domainName := ""
		if s, ok := result.Data["subdomain"].(string); ok && s != "" {
			domainName = s
		} else if d, ok := result.Data["domain"].(string); ok && d != "" {
			domainName = d
		}

		if domainName != "" {
			if serviceInfo, exists := serviceMap[domainName]; exists {
				// 补充 title
				if title, ok := serviceInfo["title"].(string); ok && title != "" {
					item["title"] = title
				}
				// 补充 status_code
				if statusCode, ok := serviceInfo["status_code"].(int32); ok {
					item["status_code"] = int(statusCode)
				} else if statusCode, ok := serviceInfo["status_code"].(int); ok {
					item["status_code"] = statusCode
				}
				// 补充 web_server
				if server, ok := serviceInfo["server"].(string); ok && server != "" {
					item["web_server"] = server
				}
				// 补充 fingerprints (技术栈)
				if techs, ok := serviceInfo["technologies"].([]interface{}); ok && len(techs) > 0 {
					var techStrings []string
					for _, t := range techs {
						if ts, ok := t.(string); ok {
							techStrings = append(techStrings, ts)
						}
					}
					item["fingerprint"] = techStrings
					item["technologies"] = techStrings
				}
				if fps, ok := serviceInfo["fingerprints"].([]interface{}); ok && len(fps) > 0 {
					var fpStrings []string
					for _, f := range fps {
						if fs, ok := f.(string); ok {
							fpStrings = append(fpStrings, fs)
						}
					}
					if item["fingerprint"] == nil {
						item["fingerprint"] = fpStrings
					}
				}
				// 补充 URL
				if url, ok := serviceInfo["url"].(string); ok && url != "" {
					item["url"] = url
				}
			}
		}

		results = append(results, item)
	}

	return results, total, nil
}

// GetPortResultsAggregated 获取聚合后的端口结果（按 IP 聚合，合并端口）
func (s *ResultService) GetPortResultsAggregated(taskID string, page, pageSize int, search string) ([]map[string]interface{}, int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, 0, err
	}

	// 使用聚合管道按 IP 分组
	matchStage := bson.M{
		"$match": bson.M{
			"task_id": objID,
			"type":    models.ResultTypePort,
		},
	}

	// 如果有搜索条件
	if search != "" {
		matchStage["$match"].(bson.M)["$or"] = []bson.M{
			{"data.ip": bson.M{"$regex": search, "$options": "i"}},
			{"data.host": bson.M{"$regex": search, "$options": "i"}},
			{"data.service": bson.M{"$regex": search, "$options": "i"}},
		}
	}

	// 按 IP 分组，收集端口信息
	groupStage := bson.M{
		"$group": bson.M{
			"_id":  "$data.ip",
			"host": bson.M{"$first": "$data.host"},
			"ports": bson.M{
				"$push": bson.M{
					"port":    "$data.port",
					"service": "$data.service",
				},
			},
			"created_at": bson.M{"$max": "$created_at"},
			"task_id":    bson.M{"$first": "$task_id"},
		},
	}

	// 排序
	sortStage := bson.M{
		"$sort": bson.M{"created_at": -1},
	}

	// 先计算总数
	countPipeline := []bson.M{matchStage, groupStage, {"$count": "total"}}
	countCursor, err := s.collection.Aggregate(ctx, countPipeline)
	if err != nil {
		return nil, 0, err
	}
	var countResult []bson.M
	if err = countCursor.All(ctx, &countResult); err != nil {
		return nil, 0, err
	}
	var total int64 = 0
	if len(countResult) > 0 {
		if t, ok := countResult[0]["total"].(int32); ok {
			total = int64(t)
		} else if t, ok := countResult[0]["total"].(int64); ok {
			total = t
		}
	}

	// 分页
	skip := int64((page - 1) * pageSize)
	skipStage := bson.M{"$skip": skip}
	limitStage := bson.M{"$limit": int64(pageSize)}

	pipeline := []bson.M{matchStage, groupStage, sortStage, skipStage, limitStage}

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			continue
		}

		ip := ""
		if v, ok := doc["_id"].(string); ok {
			ip = v
		}

		host := ""
		if v, ok := doc["host"].(string); ok {
			host = v
		}

		// 处理端口列表
		var portList []string
		var serviceList []string
		if ports, ok := doc["ports"].(bson.A); ok {
			for _, p := range ports {
				if portDoc, ok := p.(bson.M); ok {
					port := ""
					service := ""
					if v, ok := portDoc["port"].(string); ok {
						port = v
					}
					if v, ok := portDoc["service"].(string); ok {
						service = v
					}
					if port != "" {
						portList = append(portList, port)
						if service != "" {
							serviceList = append(serviceList, service)
						}
					}
				}
			}
		}

		item := map[string]interface{}{
			"ip":         ip,
			"host":       host,
			"ports":      portList,
			"port_count": len(portList),
			"services":   serviceList,
			"created_at": doc["created_at"],
		}

		results = append(results, item)
	}

	return results, total, nil
}

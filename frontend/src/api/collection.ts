import api, { ApiResponse } from '@/lib/api'

export type CollectionStageStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped'

export interface CollectionPlan {
  id: string
  project_id: number
  mode: 'auto' | 'full' | 'staged' | string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | string
  current_stage: string
  deadline?: string
  created_at: string
  updated_at: string
}

export interface CollectionStage {
  id: number
  plan_id: string
  stage: string
  task_id?: string
  status: CollectionStageStatus | string
  attempt: number
  skip_reason?: string
  started_at?: string
  finished_at?: string
  task_name?: string
  task_status?: string
  task_progress?: number
}

export interface CollectionPlanDetail {
  plan: CollectionPlan
  stages: CollectionStage[]
}

export interface CollectionPlanListResponse {
  code: number
  message: string
  data: CollectionPlan[]
  total: number
  page: number
  size: number
}

export const collectionApi = {
  listPlans: async (params?: {
    projectId?: number
    status?: string
    page?: number
    pageSize?: number
  }): Promise<CollectionPlanListResponse> => {
    const response = await api.get('/collection/plans', {
      params: {
        project_id: params?.projectId,
        status: params?.status,
        page: params?.page,
        page_size: params?.pageSize,
      },
    })
    return response as unknown as CollectionPlanListResponse
  },

  getPlan: async (id: string): Promise<ApiResponse<CollectionPlanDetail>> => {
    const response = await api.get(`/collection/plans/${id}`)
    return response as unknown as ApiResponse<CollectionPlanDetail>
  },
}

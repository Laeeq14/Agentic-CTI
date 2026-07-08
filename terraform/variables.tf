###############################################################################
# terraform/variables.tf — Input variables for Agentic-CTI infrastructure
###############################################################################

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment label (e.g. dev, staging, prod)."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "groq_api_key" {
  description = "Groq API key to store in Secrets Manager. Passed at apply time, never hardcoded."
  type        = string
  sensitive   = true
}

variable "task_cpu" {
  description = "Fargate task CPU units (256 = 0.25 vCPU)."
  type        = number
  default     = 512   # 0.5 vCPU — sufficient for inference tasks

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096], var.task_cpu)
    error_message = "task_cpu must be a valid Fargate CPU value: 256, 512, 1024, 2048, or 4096."
  }
}

variable "task_memory" {
  description = "Fargate task memory in MiB."
  type        = number
  default     = 1024   # 1 GiB — sufficient for the pipeline with model cache

  validation {
    condition     = var.task_memory >= 512 && var.task_memory <= 30720
    error_message = "task_memory must be between 512 and 30720 MiB."
  }
}

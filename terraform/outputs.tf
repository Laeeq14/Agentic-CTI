###############################################################################
# terraform/outputs.tf — Outputs for Agentic-CTI infrastructure
###############################################################################

output "alb_dns_name" {
  description = "Public DNS name of the Application Load Balancer. Use this to access the UI and API."
  value       = aws_lb.main.dns_name
}

output "ecr_fastapi_url" {
  description = "ECR repository URL for the FastAPI backend image. Push to this URL before deploying."
  value       = aws_ecr_repository.fastapi.repository_url
}

output "ecr_streamlit_url" {
  description = "ECR repository URL for the Streamlit frontend image. Push to this URL before deploying."
  value       = aws_ecr_repository.streamlit.repository_url
}

output "s3_reports_bucket" {
  description = "Name of the S3 bucket used for threat report uploads."
  value       = aws_s3_bucket.reports.bucket
}

output "groq_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the GROQ_API_KEY."
  value       = aws_secretsmanager_secret.groq_api_key.arn
  sensitive   = true
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster."
  value       = aws_ecs_cluster.main.name
}

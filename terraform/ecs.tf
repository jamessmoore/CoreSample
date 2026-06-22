resource "aws_ecs_cluster" "this" {
  name = var.project_name
}

resource "aws_cloudwatch_log_group" "ec2_audit_mcp" {
  name              = "/ecs/${var.project_name}/ec2-audit-mcp"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "iam_audit_mcp" {
  name              = "/ecs/${var.project_name}/iam-audit-mcp"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "s3_audit_mcp" {
  name              = "/ecs/${var.project_name}/s3-audit-mcp"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "report_mcp" {
  name              = "/ecs/${var.project_name}/report-mcp"
  retention_in_days = 14
}

# --- ec2-audit-mcp ------------------------------------------------------------

resource "aws_ecs_task_definition" "ec2_audit_mcp" {
  family                   = "${var.project_name}-ec2-audit-mcp"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.fargate_cpu
  memory                   = var.fargate_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ec2_audit_mcp_task.arn

  container_definitions = jsonencode([{
    name      = "ec2-audit-mcp"
    image     = "${aws_ecr_repository.ec2_audit_mcp.repository_url}:latest"
    essential = true
    portMappings = [{
      containerPort = var.container_port
      protocol      = "tcp"
    }]
    environment = [
      { name = "PORT", value = tostring(var.container_port) },
      { name = "AWS_REGION", value = var.audited_region },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.ec2_audit_mcp.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ec2-audit-mcp"
      }
    }
  }])

  # First apply needs a real image already in ECR (chicken-and-egg, same as
  # daily-tech-brief-bedrock's Lambda case) -- see README "first deploy"
  # steps: create the ECR repo, build+push :latest, then apply the rest.
}

resource "aws_lb_target_group" "ec2_audit_mcp" {
  name        = "${var.project_name}-ec2-audit"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.default.id
  target_type = "ip"

  health_check {
    path = "/health" # GET /mcp returns 406 -- the MCP route needs MCP-specific Accept headers
  }
}

resource "aws_ecs_service" "ec2_audit_mcp" {
  name            = "${var.project_name}-ec2-audit-mcp"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.ec2_audit_mcp.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.mcp_tasks.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.ec2_audit_mcp.arn
    container_name   = "ec2-audit-mcp"
    container_port   = var.container_port
  }

  depends_on = [aws_lb_listener.ec2_audit_mcp]
}

# --- iam-audit-mcp -------------------------------------------------------------

resource "aws_ecs_task_definition" "iam_audit_mcp" {
  family                   = "${var.project_name}-iam-audit-mcp"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.fargate_cpu
  memory                   = var.fargate_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.iam_audit_mcp_task.arn

  container_definitions = jsonencode([{
    name      = "iam-audit-mcp"
    image     = "${aws_ecr_repository.iam_audit_mcp.repository_url}:latest"
    essential = true
    portMappings = [{
      containerPort = var.container_port
      protocol      = "tcp"
    }]
    environment = [
      { name = "PORT", value = tostring(var.container_port) },
      { name = "AWS_REGION", value = var.audited_region },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.iam_audit_mcp.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "iam-audit-mcp"
      }
    }
  }])

  # First apply needs a real image already in ECR (chicken-and-egg, same as
  # daily-tech-brief-bedrock's Lambda case) -- see README "first deploy"
  # steps: create the ECR repo, build+push :latest, then apply the rest.
}

resource "aws_lb_target_group" "iam_audit_mcp" {
  name        = "${var.project_name}-iam-audit"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.default.id
  target_type = "ip"

  health_check {
    path = "/health" # GET /mcp returns 406 -- the MCP route needs MCP-specific Accept headers
  }
}

resource "aws_ecs_service" "iam_audit_mcp" {
  name            = "${var.project_name}-iam-audit-mcp"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.iam_audit_mcp.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.mcp_tasks.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.iam_audit_mcp.arn
    container_name   = "iam-audit-mcp"
    container_port   = var.container_port
  }

  depends_on = [aws_lb_listener.iam_audit_mcp]
}

# --- s3-audit-mcp ---------------------------------------------------------------

resource "aws_ecs_task_definition" "s3_audit_mcp" {
  family                   = "${var.project_name}-s3-audit-mcp"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.fargate_cpu
  memory                   = var.fargate_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.s3_audit_mcp_task.arn

  container_definitions = jsonencode([{
    name      = "s3-audit-mcp"
    image     = "${aws_ecr_repository.s3_audit_mcp.repository_url}:latest"
    essential = true
    portMappings = [{
      containerPort = var.container_port
      protocol      = "tcp"
    }]
    environment = [
      { name = "PORT", value = tostring(var.container_port) },
      { name = "AWS_REGION", value = var.audited_region },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.s3_audit_mcp.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "s3-audit-mcp"
      }
    }
  }])

  # First apply needs a real image already in ECR (chicken-and-egg, same as
  # daily-tech-brief-bedrock's Lambda case) -- see README "first deploy"
  # steps: create the ECR repo, build+push :latest, then apply the rest.
}

resource "aws_lb_target_group" "s3_audit_mcp" {
  name        = "${var.project_name}-s3-audit"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.default.id
  target_type = "ip"

  health_check {
    path = "/health" # GET /mcp returns 406 -- the MCP route needs MCP-specific Accept headers
  }
}

resource "aws_ecs_service" "s3_audit_mcp" {
  name            = "${var.project_name}-s3-audit-mcp"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.s3_audit_mcp.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.mcp_tasks.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.s3_audit_mcp.arn
    container_name   = "s3-audit-mcp"
    container_port   = var.container_port
  }

  depends_on = [aws_lb_listener.s3_audit_mcp]
}

# --- report-mcp ----------------------------------------------------------------

resource "aws_ecs_task_definition" "report_mcp" {
  family                   = "${var.project_name}-report-mcp"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.fargate_cpu
  memory                   = var.fargate_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.report_mcp_task.arn

  container_definitions = jsonencode([{
    name      = "report-mcp"
    image     = "${aws_ecr_repository.report_mcp.repository_url}:latest"
    essential = true
    portMappings = [{
      containerPort = var.container_port
      protocol      = "tcp"
    }]
    environment = [
      { name = "PORT", value = tostring(var.container_port) },
      { name = "REPORT_BUCKET_NAME", value = aws_s3_bucket.reports.bucket },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.report_mcp.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "report-mcp"
      }
    }
  }])
}

resource "aws_lb_target_group" "report_mcp" {
  name        = "${var.project_name}-report"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.default.id
  target_type = "ip"

  health_check {
    path = "/health" # GET /mcp returns 406 -- the MCP route needs MCP-specific Accept headers
  }
}

resource "aws_ecs_service" "report_mcp" {
  name            = "${var.project_name}-report-mcp"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.report_mcp.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.mcp_tasks.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.report_mcp.arn
    container_name   = "report-mcp"
    container_port   = var.container_port
  }

  depends_on = [aws_lb_listener.report_mcp]
}

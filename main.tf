provider "google" {
  project = var.projectID
  region  = var.region
  zone   = var.zone
}
resource "google_project_service" "enable_google_apis" {
  count   = length(var.gcp_services_list)
  project = var.projectID
  service = var.gcp_services_list[count.index] 
  disable_on_destroy=false
  disable_dependent_services =false
}
resource "google_service_account" "sa" {
  project      = var.projectID
  account_id   = "${var.deploymentName}-sa"
  display_name = "Service Account"  
}


resource "google_project_iam_member""sa_iam1" {
  project = var.projectID
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.sa.email}"
  depends_on = [
    google_service_account.sa
  ]

}
resource "google_project_iam_member""sa_iam2" {
  project = var.projectID
  role    = "roles/container.admin"
  member  = "serviceAccount:${google_service_account.sa.email}"
  depends_on = [
    google_service_account.sa
  ]

}
resource "google_service_account" "gke" {
  project      = var.projectID
  account_id   = "${var.deploymentName}-gke"
  display_name = "Service Account"  
}

resource "google_project_iam_member" "gke1" {
  project = var.projectID
  role    = "roles/container.admin"
  member  = "serviceAccount:${google_service_account.gke.email}"
  depends_on = [
    google_service_account.gke
  ]

}

resource "google_project_iam_member" "gke2" {
  project = var.projectID
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.gke.email}"
  depends_on = [
    google_service_account.gke
  ]
}

resource "google_project_iam_member" "gke3" {
  project = var.projectID
  role    = "roles/compute.instanceAdmin"
  member  = "serviceAccount:${google_service_account.gke.email}"
  depends_on = [
    google_service_account.gke
  ]

}
data "archive_file" "source" {
    type        = "zip"
    source_dir  = "./scripts"
    output_path = "/tmp/index.zip"
}

resource "google_storage_bucket" "bucket"{
  name = format("%s-bucket", var.deploymentName)
  location = var.region
  force_destroy = true  
}

resource "google_storage_bucket_object" "zip" {
    source       = data.archive_file.source.output_path
    content_type = "application/zip"    
    name         = "index.zip"
    bucket       = google_storage_bucket.bucket.name    
    depends_on   = [
        google_storage_bucket.bucket,  
        data.archive_file.source
    ]
}
resource "google_cloudfunctions_function" "function" {
  name = format("%s-LicenseValidation", var.deploymentName) 
  description = "Boomi License Validation"
  runtime     = "python37"
  service_account_email = google_service_account.sa.email
  available_memory_mb   = 256
  timeout               = 60
  source_archive_bucket = google_storage_bucket.bucket.name
  source_archive_object = google_storage_bucket_object.zip.name
  trigger_http          = true
  entry_point           = "handler" 
  depends_on = [
    google_storage_bucket.bucket
  ]   
}

locals {
  set_sensitive = sensitive(true)
}

resource "null_resource" "callfunction" {
provisioner "local-exec" {
   command=<<EOF
   curl -m 70 -X POST "https://${var.region}-${var.projectID}.cloudfunctions.net/${var.deploymentName}-LicenseValidation" -H "Authorization:bearer $(gcloud auth print-identity-token)" -H "Content-Type:application/json" -d '{"BoomiUsername":"${var.boomiUserEmailID}","boomiAuthenticationType":"${var.boomiAuthenticationType}","BoomiPassword":"${var.boomiPasswordORboomiAPIToken}","BoomiAccountID":"${var.boomiAccountID}","TokenType":"molecule","TokenTimeout":"60","bucketname": "${var.deploymentName}-bucket","atomtype": "${var.atomtype}","set_sensitive":"${local.set_sensitive}"}'
EOF
}
depends_on = [
    google_cloudfunctions_function.function
  ]
}
resource "google_compute_network" "vpc_network" {
  name = format("%s-vpc-network", var.deploymentName)
  auto_create_subnetworks = false
  depends_on = [
    google_cloudfunctions_function.function
  ]
 
}

resource "google_compute_subnetwork" "public-subnetwork" {
 name = format("%s-public-subnetwork", var.deploymentName)
 ip_cidr_range = "192.168.0.0/21"
 private_ip_google_access= true
 region = var.region
 network = google_compute_network.vpc_network.name
 depends_on = [
    google_compute_network.vpc_network
  ]
}

resource "google_compute_subnetwork" "private-subnetwork" {
 name = format("%s-private-subnetwork", var.deploymentName)
 ip_cidr_range = "192.168.8.0/21"
 region = var.region
 network = google_compute_network.vpc_network.name
 depends_on = [
    google_compute_network.vpc_network
  ]
}


resource "google_compute_router" "router" {
  name = format("%s-router", var.deploymentName)
  region  = var.region
  network = google_compute_network.vpc_network.name
   depends_on = [
    google_compute_subnetwork.private-subnetwork
  ]
}

resource "google_compute_router_nat" "nat_manual" {
  name = format("%s-nat", var.deploymentName)
  router = google_compute_router.router.name
  region = var.region
  nat_ip_allocate_option = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
  subnetwork {
    name                    = google_compute_subnetwork.private-subnetwork.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
  depends_on = [
    google_compute_router.router
  ]
}
  

resource "google_compute_firewall" "firewall1" {
  name = format("%s-firewall1", var.deploymentName)
  network = google_compute_network.vpc_network.name
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["10.0.0.0/8"] 
  target_tags   = ["externalssh"]
  depends_on = [
    google_compute_subnetwork.public-subnetwork
  ] 

}

resource "google_compute_instance" "vm1" {
  name = format("%s-bastion-host", var.deploymentName)
  machine_type = var.machineType
  tags = ["externalssh"]

  boot_disk {
    initialize_params {
      image = "centos-cloud/centos-7"
    }
  }

  network_interface {
    network = google_compute_network.vpc_network.name
    subnetwork = google_compute_subnetwork.public-subnetwork.name

    access_config {    
    }
  }
  service_account {        
    email  = google_service_account.sa.email
    scopes = ["cloud-platform"]
    }
  depends_on = [
    google_compute_subnetwork.public-subnetwork
  ]
}

resource "google_container_cluster" "primary" {
  name     = "my-gke-cluster"
  location = "us-central1"
  network = google_compute_network.vpc_network.name
  subnetwork = google_compute_subnetwork.private-subnetwork.self_link
  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"
  master_authorized_networks_config {
    cidr_blocks {
      display_name = "bastion"
      cidr_block   = format("%s/32", google_compute_instance.vm1.network_interface.0.network_ip)
    } 
  }
  private_cluster_config {
    enable_private_endpoint = "false"
    enable_private_nodes    = "true"
    master_ipv4_cidr_block  = "172.16.0.16/28"
  }
  ip_allocation_policy {
    cluster_ipv4_cidr_block  = "10.1.0.0/16"
    services_ipv4_cidr_block = "10.2.0.0/16"
  }
  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1
}

resource "google_container_node_pool" "primary_preemptible_nodes" {
  name       = "my-node-pool"
  location   = "us-central1"
  cluster    = google_container_cluster.primary.name
  node_count = 1
 
  autoscaling {
    min_node_count=3
    max_node_count=10
  }

  node_config {
    preemptible  = true
    machine_type = "e2-medium"
    service_account = google_service_account.gke.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
       
  }
}
 
resource "google_filestore_instance" "instance" {
  name = "test-instance"
  location = "us-central1-b"
  tier = "STANDARD"

  file_shares {
    capacity_gb = 1024
    name        = "share1"

    nfs_export_options {
      ip_ranges = ["10.0.0.0/24"]
      access_mode = "READ_WRITE"
      squash_mode = "NO_ROOT_SQUASH"
   }

   nfs_export_options {
      ip_ranges = ["10.10.0.0/24"]
      access_mode = "READ_ONLY"
      squash_mode = "ROOT_SQUASH"      
   }
  }

  networks {
    network = google_compute_network.vpc_network.name
    modes   = ["MODE_IPV4"]
    connect_mode = "DIRECT_PEERING"
  }
}

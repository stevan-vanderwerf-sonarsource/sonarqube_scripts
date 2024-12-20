#!/bin/bash

# Set your SonarQube server URL and authentication token
SONARQUBE_URL="http://localhost:9000"
AUTH_TOKEN="" # must by user token with administer permission

# Output CSV file
OUTPUT_FILE="vulnerabilities.csv"

# Write CSV header
echo "projectKey,branch,path,message,ruleReference,severity" > "$OUTPUT_FILE"

# Initialize pagination variables
page=1
page_size=500
total_projects=1

# Loop through pages until there are no more projects
while [ $page -le $total_projects ]; do
    # Make the API request to get the projects with pagination
    response=$(curl -s -u "$AUTH_TOKEN:" "$SONARQUBE_URL/api/projects/search?p=$page&ps=$page_size")

    # Check if the response is valid
    if [ $? -ne 0 ]; then
        echo "Failed to connect to SonarQube API."
        exit 1
    fi

    # Extract total number of projects and project keys using jq
    total_projects=$(echo "$response" | jq -r '.paging.total')
    project_keys=$(echo "$response" | jq -r '.components[].key')

    # Check if jq command was successful
    if [ $? -ne 0 ]; then
        echo "Failed to parse JSON response."
        exit 1
    fi

    # Loop through each project key to get vulnerability findings
    for project_key in $project_keys; do
        # Make the API request to get findings for the project
        findings_response=$(curl -s -u "$AUTH_TOKEN:" "$SONARQUBE_URL/api/projects/export_findings?project=$project_key")

        # Check if the response is valid
        if [ $? -ne 0 ]; then
            echo "Failed to connect to SonarQube API for project $project_key."
            continue
        fi

        # Extract vulnerability findings using jq
        vulnerabilities=$(echo "$findings_response" | jq -c '.export_findings[] | select(.type == "VULNERABILITY") | {projectKey, branch, path, message, ruleReference, severity}')

        # Check if jq command was successful
        if [ $? -ne 0 ]; then
            echo "Failed to parse JSON response for project $project_key."
            continue
        fi

        # Only process if there are vulnerabilities
        if [ -n "$vulnerabilities" ]; then
            # Append each vulnerability to the CSV file
            echo "$vulnerabilities" | while IFS= read -r vulnerability; do
                # Convert JSON to CSV format
                projectKey=$(echo "$vulnerability" | jq -r '.projectKey')
                branch=$(echo "$vulnerability" | jq -r '.branch')
                path=$(echo "$vulnerability" | jq -r '.path')
                message=$(echo "$vulnerability" | jq -r '.message')
                ruleReference=$(echo "$vulnerability" | jq -r '.ruleReference')
                severity=$(echo "$vulnerability" | jq -r '.severity')

                # Append to CSV file
                echo "$projectKey,$branch,$path,$message,$ruleReference,$severity" >> "$OUTPUT_FILE"
            done
        fi
    done

    # Increment the page number for the next iteration
    ((page++))
done

echo "Vulnerability findings exported to $OUTPUT_FILE."
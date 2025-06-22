#!/bin/bash

# Ensure the script receives a directory argument
TF_DIRECTORY=${1}
if [[ -z "$TF_DIRECTORY" ]]; then
  echo "##vso[task.logissue type=error] No directory provided."
  exit 1
fi

errors=0

# Loop through all Terraform (.tf) files in the provided directory
for file in $(find "$TF_DIRECTORY" -name "*.tf"); do
  inside_module=0  # Flag to track if we're inside a module block
  module_block=""  # Variable to store the module block content
  brace_count=0    # Tracks { and } balance

  # Read each line from the Terraform file
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Detect module block start
    if [[ $line =~ ^module\ \" ]]; then
      inside_module=1
      brace_count=0  # Reset brace counter
      module_block="$line"
      ((brace_count++))  # Count the opening {
      continue
    fi

    # If inside a module block, keep adding lines to the variable
    if [[ $inside_module -eq 1 ]]; then
      module_block+="\n$line"

      # Count opening and closing braces to track nested blocks
      if [[ $line =~ \{ ]]; then
        ((brace_count++))
      fi
      if [[ $line =~ \} ]]; then
        ((brace_count--))
      fi
    fi

    # If brace count reaches zero, module block is fully captured
    if [[ $inside_module -eq 1 && $brace_count -eq 0 ]]; then
      inside_module=0  # Reset flag

      # Check if the module uses Terraform Cloud private registry
      if echo -e "$module_block" | grep -q 'source\s*=\s*".*app\.terraform\.io.*"'; then
        # Check if "version" exists in the module block
        if ! echo -e "$module_block" | grep -q 'version\s*='; then
          echo "❌ ERROR: Missing 'version' in module source in $file"
          echo -e "❌ Module Block:\n$module_block"
          echo "❌ Please specify a 'version' property in the module block."
          errors=1
        else
          echo -e "✅ TFC Module versioned correctly: $module_block" | head -n 1
        fi
      fi
    fi
  done < "$file"
done

# Exit with error code if any issues were found
if [[ $errors -ne 0 ]]; then
  exit 1
fi

echo "✅ All TFC modules (if any) have valid versions."

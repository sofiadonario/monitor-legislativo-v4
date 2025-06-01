#!/bin/bash
# Process all CSV files with location separator

echo "=== Processing all CSV files with location separator ==="
echo "Date: $(date)"

# Count total CSV files
total_files=$(ls -1 *.csv | grep -v "_localidades_separadas" | wc -l)
current=0

for file in *.csv; do
    # Skip already processed files
    if [[ $file == *"_localidades_separadas.csv" ]]; then
        continue
    fi
    
    current=$((current + 1))
    output_file="${file%.csv}_localidades_separadas.csv"
    
    echo "[$current/$total_files] Processing: $file"
    
    if [[ -f "$output_file" ]]; then
        echo "  -> Already exists: $output_file (skipping)"
        continue
    fi
    
    python3 separar_localidades.py "$file" "$output_file"
    
    if [[ $? -eq 0 ]]; then
        echo "  -> Success: $output_file"
    else
        echo "  -> Error processing: $file"
    fi
    
    echo ""
done

echo "=== Processing complete ==="
echo "Total files processed: $current"
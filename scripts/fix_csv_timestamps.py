import csv
import os

def fix_csv_timestamps():
    """
    Reads the source CSV, fixes malformed timestamps in the 'date_searched'
    column, and writes to a new cleaned CSV file.
    """
    source_file = 'data/processed/lexml_parsed_enhanced_fixed.csv'
    target_file = 'data/processed/lexml_parsed_enhanced_fixed_cleaned.csv'
    
    print(f"Attempting to fix timestamps in '{source_file}'...")

    if not os.path.exists(source_file):
        print(f"❌ ERROR: Source file not found at '{source_file}'")
        return

    cleaned_rows = []
    try:
        with open(source_file, 'r', encoding='utf-8') as f_in:
            reader = csv.reader(f_in)
            header = next(reader)
            cleaned_rows.append(header)
            
            # Find the index of the column to fix
            try:
                date_column_index = header.index('date_searched')
            except ValueError:
                print("❌ ERROR: 'date_searched' column not found in the CSV header.")
                return

            fix_count = 0
            for i, row in enumerate(reader):
                if len(row) > date_column_index:
                    original_date = row[date_column_index]
                    # Check if the date string contains a space and is longer than a standard timestamp
                    if ' ' in original_date and len(original_date) > 19:
                        # Split by space and take the first two parts (date and time)
                        parts = original_date.split(' ')
                        if len(parts) > 2:
                            corrected_date = f"{parts[0]} {parts[1]}"
                            row[date_column_index] = corrected_date
                            fix_count += 1
                cleaned_rows.append(row)
        
        print(f"✅ Found and corrected {fix_count} malformed timestamps.")

        with open(target_file, 'w', encoding='utf-8', newline='') as f_out:
            writer = csv.writer(f_out)
            writer.writerows(cleaned_rows)
            
        print(f"✅ Successfully wrote cleaned data to '{target_file}'")

    except Exception as e:
        print(f"❌ An error occurred: {e}")

if __name__ == "__main__":
    fix_csv_timestamps() 
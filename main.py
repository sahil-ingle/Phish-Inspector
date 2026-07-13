from detector.parser import parse_eml
from detector.header_checker import check_headers
from detector.url_checker import check_urls
from detector.report import print_module_result

email = parse_eml("sample_emails/sample1.eml")

url_analysis = input("Do you want offline URL analysis? (Y/N): ").strip().lower()

results = [
    check_headers(email)
]

if url_analysis == "y":
    results.append(check_urls(email))

overall_score = 0

for result in results:
    print_module_result(result)
    overall_score += result["score"]

print(f"\nOverall Risk Score: {overall_score}")
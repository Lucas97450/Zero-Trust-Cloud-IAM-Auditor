from .json_reporter import save_json_report
from .markdown_reporter import save_markdown_report

def save_report(result, out_dir: str):
    save_json_report(result, out_dir)
    save_markdown_report(result, out_dir)

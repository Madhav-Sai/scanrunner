"""Optional workbook rendering with explicit text cells and atomic publication."""
import json
import os
from pathlib import Path
import tempfile


def workbook(sections, destination):
    try:
        from openpyxl import Workbook
    except ImportError as error:
        raise ValueError("XLSX export requires the optional openpyxl package") from error
    destination = Path(destination).resolve()
    book = Workbook()
    book.remove(book.active)
    for name, rows in sections.items():
        sheet = book.create_sheet(name)
        fields = list(dict.fromkeys(key for row in rows for key in row))
        sheet.append(fields)
        for row in rows:
            values = [json.dumps(row.get(field), ensure_ascii=False) if isinstance(row.get(field), (dict, list))
                      else row.get(field, "Not determined") for field in fields]
            if any(isinstance(value, str) and len(value) > 32767 for value in values):
                raise ValueError("A workbook cell exceeds Excel's text limit")
            sheet.append(values)
            for cell in sheet[sheet.max_row]:
                if isinstance(cell.value, str):
                    cell.data_type = "s"
        for cell in sheet[1]:
            cell.data_type = "s"
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = sheet.dimensions
    descriptor, temporary = tempfile.mkstemp(prefix=".scanrunner-export-", suffix=".xlsx", dir=destination.parent)
    os.close(descriptor)
    try:
        book.save(temporary)
        os.replace(temporary, destination)
    finally:
        book.close()
        if os.path.exists(temporary):
            os.unlink(temporary)

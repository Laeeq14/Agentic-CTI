"""Patch: add unmapped_ttps to navigator layer metadata block."""
with open("src/navigator/navigator_export.py", encoding="utf-8") as f:
    content = f.read()

old = (
    '            {\n'
    '                "name": "layer_id",\n'
    '                "value": str(uuid.uuid4()),\n'
    '            },\n'
    '        ],'
)
new = (
    '            {\n'
    '                "name": "layer_id",\n'
    '                "value": str(uuid.uuid4()),\n'
    '            },\n'
    '            *(\n'
    '                [{"name": "unmapped_ttps", "value": ", ".join(unmapped_ttps)}]\n'
    '                if unmapped_ttps else []\n'
    '            ),\n'
    '        ],'
)

if old in content:
    content = content.replace(old, new, 1)
    with open("src/navigator/navigator_export.py", "w", encoding="utf-8") as f:
        f.write(content)
    print("PATCHED OK")
else:
    print("NOT FOUND")
    idx = content.find("layer_id")
    print(repr(content[idx - 5:idx + 120]))

#!/usr/bin/env python3
"""Generate CycloneDX 1.5 and SPDX 2.3 SBOMs from conda package metadata.

Called from build.sh/bld.bat during package build. Reads environment variables
set by conda-build and optionally parses meta.yaml for dependencies.

For EU CRA compliance, SBOMs include:
- Full component metadata (versions, licenses, purls)
- License declarations for all dependencies
- Package URLs for unique identification

Usage:
    python generate-sbom.py [--meta-yaml PATH] [--components PATH] [--output-dir PATH] [--validate]

Environment variables (set by conda-build):
    PKG_NAME, PKG_VERSION, PKG_LICENSE, PREFIX, RECIPE_DIR
"""

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


def parse_meta_yaml(meta_yaml_path: Path) -> dict:
    """Parse meta.yaml to extract package info and dependencies.

    This is a simple parser that handles common patterns without requiring
    conda-build's full rendering engine.
    """
    if not meta_yaml_path.exists():
        return {}

    content = meta_yaml_path.read_text()
    result = {
        "name": "",
        "version": "",
        "license": "",
        "summary": "",
        "home": "",
        "run_deps": [],
        "host_deps": [],
    }

    jinja_vars = {}
    for match in re.finditer(r'\{%\s*set\s+(\w+)\s*=\s*["\']([^"\']+)["\']\s*%\}', content):
        jinja_vars[match.group(1)] = match.group(2)

    result["name"] = jinja_vars.get("name", "")
    result["version"] = jinja_vars.get("version", "")

    def expand_jinja(text: str) -> str:
        for var, val in jinja_vars.items():
            text = re.sub(r"\{\{\s*" + var + r"\s*\}\}", val, text)
        return text

    license_match = re.search(r"^\s*license:\s*(.+)$", content, re.MULTILINE)
    if license_match:
        result["license"] = expand_jinja(license_match.group(1).strip())

    summary_match = re.search(r"^\s*summary:\s*(.+)$", content, re.MULTILINE)
    if summary_match:
        result["summary"] = expand_jinja(summary_match.group(1).strip())

    home_match = re.search(r"^\s*home:\s*(.+)$", content, re.MULTILINE)
    if home_match:
        result["home"] = expand_jinja(home_match.group(1).strip())

    in_run = False
    in_host = False
    for line in content.split("\n"):
        stripped = line.strip()

        if stripped.startswith("run:"):
            in_run = True
            in_host = False
            continue
        elif stripped.startswith("host:"):
            in_host = True
            in_run = False
            continue
        elif stripped and not stripped.startswith("-") and not stripped.startswith("#"):
            if ":" in stripped:
                in_run = False
                in_host = False

        if stripped.startswith("- ") and (in_run or in_host):
            dep = stripped[2:].strip()
            dep = re.sub(r"\s*#\s*\[.*\]", "", dep)
            dep = expand_jinja(dep)
            dep_name = re.split(r"[\s<>=!]", dep)[0].strip()

            if dep_name and dep_name not in ("python", "pip"):
                if in_run:
                    result["run_deps"].append(dep_name)
                elif in_host:
                    result["host_deps"].append(dep_name)

    return result


def load_components(components_path: Path) -> list[dict]:
    """Load component metadata from JSON file.

    Expected format:
    [
        {
            "name": "package-name",
            "version": "1.2.3",
            "license": "MIT",
            "purl": "pkg:pypi/package-name@1.2.3"
        },
        ...
    ]
    """
    if not components_path or not components_path.exists():
        return []

    try:
        return json.loads(components_path.read_text())
    except Exception:
        return []


def generate_cyclonedx(
    pkg_name: str,
    pkg_version: str,
    license_id: str,
    dependencies: list[str],
    timestamp: str,
    serial_number: str,
    summary: str = "",
    home_url: str = "",
    components: list[dict] | None = None,
) -> dict:
    """Generate CycloneDX 1.5 SBOM with full component metadata."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "conda-build",
                        "publisher": "Anaconda, Inc.",
                    },
                    {
                        "type": "application",
                        "name": "generate-sbom.py",
                        "publisher": "Anaconda, Inc.",
                    },
                ]
            },
            "supplier": {"name": "Anaconda, Inc.", "url": ["https://www.anaconda.com"]},
            "component": {
                "type": "library",
                "name": pkg_name,
                "version": pkg_version,
                "purl": f"pkg:conda/{pkg_name}@{pkg_version}",
                "licenses": [{"license": {"id": license_id}}] if license_id else [],
                "supplier": {
                    "name": "Anaconda, Inc.",
                    "url": ["https://www.anaconda.com"],
                },
            },
        },
        "components": [],
        "licenses": [],
    }

    if summary:
        sbom["metadata"]["component"]["description"] = summary
    if home_url:
        sbom["metadata"]["component"]["externalReferences"] = [{"type": "website", "url": home_url}]

    seen_licenses = set()
    if license_id and license_id != "UNKNOWN":
        seen_licenses.add(license_id)
        sbom["licenses"].append({"license": {"id": license_id}})

    if components:
        for comp in components:
            comp_license = comp.get("license", "")
            comp_entry = {
                "type": "library",
                "name": comp["name"],
                "version": comp.get("version", ""),
                "purl": comp.get("purl", f"pkg:conda/{comp['name']}@{comp.get('version', '')}"),
            }
            if comp_license:
                comp_entry["licenses"] = [{"license": {"id": comp_license}}]
                if comp_license not in seen_licenses:
                    seen_licenses.add(comp_license)
                    sbom["licenses"].append({"license": {"id": comp_license}})
            sbom["components"].append(comp_entry)
    else:
        for dep in dependencies:
            sbom["components"].append(
                {
                    "type": "library",
                    "name": dep,
                    "purl": f"pkg:conda/{dep}",
                }
            )

    return sbom


def generate_spdx(
    pkg_name: str,
    pkg_version: str,
    license_id: str,
    dependencies: list[str],
    timestamp: str,
    doc_uuid: str,
    summary: str = "",
    home_url: str = "",
    components: list[dict] | None = None,
) -> dict:
    """Generate SPDX 2.3 SBOM with full component metadata."""
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{pkg_name}-{pkg_version}",
        "documentNamespace": f"https://anaconda.com/spdx/{pkg_name}/{pkg_version}/{doc_uuid}",
        "creationInfo": {
            "created": timestamp,
            "creators": [
                "Tool: conda-build",
                "Tool: generate-sbom.py",
                "Organization: Anaconda, Inc.",
            ],
            "licenseListVersion": "3.21",
        },
        "packages": [
            {
                "SPDXID": f"SPDXRef-Package-{pkg_name.replace('-', '_')}",
                "name": pkg_name,
                "versionInfo": pkg_version,
                "supplier": "Organization: Anaconda, Inc.",
                "downloadLocation": f"https://anaconda.org/anaconda/{pkg_name}",
                "filesAnalyzed": False,
                "primaryPackagePurpose": "LIBRARY",
                "licenseConcluded": license_id if license_id else "NOASSERTION",
                "licenseDeclared": license_id if license_id else "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:conda/{pkg_name}@{pkg_version}",
                    }
                ],
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": f"SPDXRef-Package-{pkg_name.replace('-', '_')}",
                "relationshipType": "DESCRIBES",
            }
        ],
        "hasExtractedLicensingInfos": [],
    }

    if summary:
        sbom["packages"][0]["summary"] = summary
    if home_url:
        sbom["packages"][0]["homepage"] = home_url

    if components:
        for comp in components:
            dep_name = comp["name"]
            dep_version = comp.get("version", "NOASSERTION")
            dep_license = comp.get("license", "NOASSERTION")
            dep_spdxid = f"SPDXRef-Package-{dep_name.replace('-', '_')}"

            sbom["packages"].append(
                {
                    "SPDXID": dep_spdxid,
                    "name": dep_name,
                    "versionInfo": dep_version,
                    "downloadLocation": comp.get("download_url", "NOASSERTION"),
                    "filesAnalyzed": False,
                    "licenseConcluded": dep_license,
                    "licenseDeclared": dep_license,
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": comp.get("purl", f"pkg:conda/{dep_name}@{dep_version}"),
                        }
                    ],
                }
            )
            sbom["relationships"].append(
                {
                    "spdxElementId": f"SPDXRef-Package-{pkg_name.replace('-', '_')}",
                    "relatedSpdxElement": dep_spdxid,
                    "relationshipType": "DEPENDS_ON",
                }
            )
    else:
        for dep in dependencies:
            dep_spdxid = f"SPDXRef-Package-{dep.replace('-', '_')}"
            sbom["packages"].append(
                {
                    "SPDXID": dep_spdxid,
                    "name": dep,
                    "versionInfo": "NOASSERTION",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": f"pkg:conda/{dep}",
                        }
                    ],
                }
            )
            sbom["relationships"].append(
                {
                    "spdxElementId": f"SPDXRef-Package-{pkg_name.replace('-', '_')}",
                    "relatedSpdxElement": dep_spdxid,
                    "relationshipType": "DEPENDS_ON",
                }
            )

    return sbom


def validate_cyclonedx(sbom: dict) -> list[str]:
    """Basic validation of CycloneDX SBOM structure."""
    errors = []

    if sbom.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be 'CycloneDX'")
    if sbom.get("specVersion") != "1.5":
        errors.append("specVersion must be '1.5'")
    if not sbom.get("serialNumber", "").startswith("urn:uuid:"):
        errors.append("serialNumber must be a URN UUID")
    if "metadata" not in sbom:
        errors.append("metadata is required")
    elif "component" not in sbom["metadata"]:
        errors.append("metadata.component is required")
    else:
        comp = sbom["metadata"]["component"]
        if "type" not in comp:
            errors.append("metadata.component.type is required")
        if "name" not in comp:
            errors.append("metadata.component.name is required")

    return errors


def validate_spdx(sbom: dict) -> list[str]:
    """Basic validation of SPDX SBOM structure."""
    errors = []

    if sbom.get("spdxVersion") != "SPDX-2.3":
        errors.append("spdxVersion must be 'SPDX-2.3'")
    if sbom.get("dataLicense") != "CC0-1.0":
        errors.append("dataLicense must be 'CC0-1.0'")
    if sbom.get("SPDXID") != "SPDXRef-DOCUMENT":
        errors.append("SPDXID must be 'SPDXRef-DOCUMENT'")
    if not sbom.get("name"):
        errors.append("name is required")
    if not sbom.get("documentNamespace"):
        errors.append("documentNamespace is required")
    if "creationInfo" not in sbom:
        errors.append("creationInfo is required")
    elif not sbom["creationInfo"].get("creators"):
        errors.append("creationInfo.creators is required")
    if not sbom.get("packages"):
        errors.append("at least one package is required")

    return errors


def main():
    parser = argparse.ArgumentParser(description="Generate CycloneDX and SPDX SBOMs")
    parser.add_argument("--meta-yaml", type=Path, help="Path to meta.yaml")
    parser.add_argument(
        "--components",
        type=Path,
        help="Path to components.json with dependency metadata",
    )
    parser.add_argument("--output-dir", type=Path, help="Output directory for SBOMs")
    parser.add_argument("--validate", action="store_true", help="Validate generated SBOMs")
    args = parser.parse_args()

    pkg_name = os.environ.get("PKG_NAME", "")
    pkg_version = os.environ.get("PKG_VERSION", "")
    license_id = os.environ.get("PKG_LICENSE", "UNKNOWN")
    prefix = os.environ.get("PREFIX", "")
    recipe_dir = os.environ.get("RECIPE_DIR", "")

    meta_info = {}
    meta_yaml_path = args.meta_yaml
    if not meta_yaml_path and recipe_dir:
        meta_yaml_path = Path(recipe_dir) / "meta.yaml"
    if meta_yaml_path and meta_yaml_path.exists():
        meta_info = parse_meta_yaml(meta_yaml_path)

    if not pkg_name:
        pkg_name = meta_info.get("name", "unknown")
    if not pkg_version:
        pkg_version = meta_info.get("version", "0.0.0")
    if license_id == "UNKNOWN" and meta_info.get("license"):
        license_id = meta_info["license"]

    dependencies = meta_info.get("run_deps", [])
    summary = meta_info.get("summary", "")
    home_url = meta_info.get("home", "")

    components_path = args.components
    if not components_path and recipe_dir:
        components_path = Path(recipe_dir).parent / "components.json"
    components = load_components(components_path)

    output_dir = args.output_dir
    if not output_dir:
        if prefix:
            output_dir = Path(prefix) / "share" / "sbom"
        else:
            output_dir = Path(".")
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_uuid = str(uuid.uuid4())

    cyclonedx = generate_cyclonedx(
        pkg_name=pkg_name,
        pkg_version=pkg_version,
        license_id=license_id,
        dependencies=dependencies,
        timestamp=timestamp,
        serial_number=doc_uuid,
        summary=summary,
        home_url=home_url,
        components=components if components else None,
    )

    spdx = generate_spdx(
        pkg_name=pkg_name,
        pkg_version=pkg_version,
        license_id=license_id,
        dependencies=dependencies,
        timestamp=timestamp,
        doc_uuid=doc_uuid,
        summary=summary,
        home_url=home_url,
        components=components if components else None,
    )

    if args.validate:
        cdx_errors = validate_cyclonedx(cyclonedx)
        spdx_errors = validate_spdx(spdx)

        if cdx_errors:
            print(f"CycloneDX validation errors: {cdx_errors}", file=sys.stderr)
        if spdx_errors:
            print(f"SPDX validation errors: {spdx_errors}", file=sys.stderr)

        if cdx_errors or spdx_errors:
            sys.exit(1)

    cdx_path = output_dir / f"{pkg_name}-{pkg_version}.cdx.json"
    spdx_path = output_dir / f"{pkg_name}-{pkg_version}.spdx.json"

    with open(cdx_path, "w") as f:
        json.dump(cyclonedx, f, indent=2)

    with open(spdx_path, "w") as f:
        json.dump(spdx, f, indent=2)

    print(f"Generated: {cdx_path}")
    print(f"Generated: {spdx_path}")

    if components:
        print(f"Included {len(components)} components with full metadata")
    elif dependencies:
        print(f"Included {len(dependencies)} dependencies (basic info only)")


if __name__ == "__main__":
    main()

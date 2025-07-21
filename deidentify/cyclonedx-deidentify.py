#!/usr/bin/env python3

##############################################################################
# cyclonedx-deidentify.py
#
# This Python 3-based CLI provides options and arguments to read in a
# CycloneDx-formatted JSON or XML SBOM, following any arbitrary spec version,
# and de-identify metadata and components (removing them), outputting it as a
# new and valid CycloneDx SBOM.
#
##############################################################################

import argparse
import json
import uuid
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from cyclonedx.model.bom import Bom, Dependency
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.schema import SchemaVersion
from cyclonedx.model.component import ComponentType
from cyclonedx.output.json import BY_SCHEMA_VERSION
from cyclonedx.output import OutputFormat, make_outputter


def load_and_validate_sbom(input_file: str) -> tuple[Bom, SchemaVersion]:
    """
    Load and validate an SBOM file (JSON or XML)

    Args:
        input_file (str): Path to the input SBOM file

    Returns:
        tuple[Bom, SchemaVersion]: A tuple containing the validated BOM object and its schema version

    Raises:
        ValueError: If the SBOM cannot be loaded or validated
    """
    with open(input_file, 'r', encoding='utf-8') as f:
        data = f.read()

    stripped = data.lstrip()

    try:
        if stripped.startswith('{'):
            parsed = json.loads(data)
            spec_version_str = parsed.get('specVersion', '1.6')
            bom = Bom.from_json(parsed)
        elif stripped.startswith('<'):
            root = ET.fromstring(data)
            spec_version_str = root.attrib.get('specVersion', '1.6')
            bom = Bom.from_xml(data)
        else:
            raise ValueError("Unsupported SBOM format — not JSON or XML")

        try:
            schema_version = getattr(
                SchemaVersion, f'V{
                    spec_version_str.replace(
                        ".", "_")}')
        except AttributeError:
            raise ValueError(f"Unsupported specVersion: {spec_version_str}")

        bom.validate()
        return bom, schema_version

    except Exception as e:
        raise ValueError(f"Failed to load or validate SBOM: {e}")


def redact_metadata_and_filter(
        bom: Bom, replacement: str, filter_criteria: dict) -> Bom:
    """
    Redact sensitive metadata in the BOM and filter out components based on given criteria.
    Also removes matching external references and cleans up dependencies.

    Args:
        bom (Bom): The BOM object to redact and filter.
        replacement (str): The replacement string for sensitive metadata.
        filter_criteria (dict): Criteria used to filter components.

    Returns:
        Bom: The redacted and filtered BOM object.
    """
    from cyclonedx.model.component import Component

    if not bom.metadata:
        bom.metadata = Bom.Metadata()

    bom.metadata.timestamp = datetime.now(timezone.utc)

    if bom.metadata.authors:
        for author in bom.metadata.authors:
            author.name = replacement
            author.email = replacement + "@NOWHERE.COM"
            author.phone = replacement

    if not bom.metadata.component or bom.metadata.component.bom_ref is None:
        # Create a new metadata.component with a bom_ref if missing or bom_ref
        # is missing
        bom.metadata.component = Component(
            name=replacement,
            version="",
            component_type=ComponentType.DEVICE,
            author=replacement,
            bom_ref=BomRef(str(uuid.uuid4()))
        )
    else:
        # Redact existing component fields
        mc = bom.metadata.component
        mc.author = replacement
        mc.name = replacement
        mc.type = ComponentType.DEVICE

    # Always add the dependency for the metadata.component
    bom.dependencies.add(Dependency(ref=bom.metadata.component.bom_ref))

    if bom.serial_number:
        bom.serial_number = uuid.uuid4()

    meta_author = bom.metadata.component.author
    meta_name = bom.metadata.component.name

    removed_bom_refs = set()
    filtered_components = []

    for comp in bom.components:
        # Remove matching externalReferences first
        if comp.external_references:
            comp.external_references = [
                ref for ref in comp.external_references
                if not (
                    filter_criteria.get('external') and
                    any(val.lower() in str(ref.url).lower()
                        for val in filter_criteria['external'])
                )
            ]

        # Check component-level filters (case-insensitive substring matching)
        if meta_author in [comp.author, comp.publisher]:
            removed_bom_refs.add(comp.bom_ref)
            continue
        if meta_name == comp.name:
            removed_bom_refs.add(comp.bom_ref)
            continue

        if any(
            values and any(
                val.lower() in str(getattr(comp, key, '')).lower() for val in values
            )
            for key, values in filter_criteria.items() if key != 'external'
        ):
            removed_bom_refs.add(comp.bom_ref)
            continue

        filtered_components.append(comp)

    bom.components = filtered_components

    # Clean up dependencies for removed components
    initial_dep_count = len(bom.dependencies)
    bom.dependencies = {
        dep for dep in bom.dependencies
        if dep.ref not in removed_bom_refs
    }
    deps_removed = initial_dep_count - len(bom.dependencies)

    print(
        f"Filtered out {
            len(removed_bom_refs)} components and removed {deps_removed} dependency entries.")

    return bom


def export_sbom(bom: Bom, output_file: str, output_format: str = 'json',
                schema_version: SchemaVersion = None) -> None:
    """
    Export the BOM object to a file in the specified format (JSON or XML)

    Args:
        bom (Bom): The BOM object to export
        output_file (str): Path to the output file
        output_format (str): The output format ('json' or 'xml')
        schema_version (SchemaVersion, optional): The schema version for export

    Returns:
        None

    Raises:
        ValueError: If the export process fails
    """
    try:
        bom.validate()

        if output_format == "json":
            BY_SCHEMA_VERSION[schema_version](
                bom=bom).output_to_file(
                output_file, allow_overwrite=True, indent=4)
        elif output_format == "xml":
            serializer = make_outputter(bom, OutputFormat.XML, schema_version)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(serializer.output_as_string(pretty=True))
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

        print(
            f"Output SBOM validated and written successfully to '{output_file}'.")

    except Exception as e:
        raise ValueError(f"Failed to export SBOM: {e}")


def deidentify_sbom(input_file: str, output_file: str, replacement: str = 'REDACTED',
                    output_format: str = 'json', filters: dict = None) -> None:
    """
    Orchestrate SBOM de-identification by redacting metadata and filtering components

    Args:
        input_file (str): Path to the input SBOM file
        output_file (str): Path to the output de-identified SBOM file
        replacement (str): Replacement string for sensitive fields
        output_format (str): Desired output format ('json' or 'xml')
        filters (dict, optional): Filtering criteria

    Returns:
        None
    """
    if filters is None:
        filters = {}

    bom, schema_version = load_and_validate_sbom(input_file)
    bom = redact_metadata_and_filter(bom, replacement, filters)
    export_sbom(bom, output_file, output_format, schema_version)


def main() -> None:
    """
    Entry point for command-line interface.

    Returns:
        None
    """
    parser = argparse.ArgumentParser(
        description=(
            "De-identify CycloneDX SBOM (JSON or XML)\n"
            "Redact metadata, filter components, remove matching external references, re-validate output\n\n"
            "Filtering examples:\n"
            "  --filter-name \"Windows\"                 # Filter components named 'Windows'\n"
            "  --filter-publisher \"Microsoft\"          # Filter components published by 'Microsoft'\n"
            "  --filter-type \"operating-system\"        # Filter components of type 'operating-system'\n"
            "  --filter-version \"10.0.0\"               # Filter components with version '10.0.0'\n"
            "  --filter-external \"microsoft.com\"       # Remove external references containing 'microsoft.com'\n\n"
            "Example usage:\n"
            "  ./cyclonedx-deidentify.py sbom.json deidentified.json "
            "--filter-name \"Windows\" --filter-publisher \"Microsoft\" "
            "--filter-type \"operating-system\" --filter-version \"10.0.0\" "
            "--filter-external \"microsoft.com\"\n\n"
            "This would remove:\n"
            "- Any components named 'Windows'\n"
            "- Any components published by 'Microsoft'\n"
            "- Any components of type 'operating-system'\n"
            "- Any components with version '10.0.0'\n"
            "- Any external references containing 'microsoft.com'\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('input', help='Input SBOM file (JSON or XML)')
    parser.add_argument('output', help='Output de-identified SBOM file')
    parser.add_argument(
        '--replacement',
        default='REDACTED',
        help='Replacement string for sensitive fields')
    parser.add_argument(
        '--output-format',
        choices=[
            'json',
            'xml'],
        default='json',
        help='Output SBOM format')

    parser.add_argument(
        '--filter-type',
        nargs='+',
        help='Filter components by type')
    parser.add_argument(
        '--filter-name',
        nargs='+',
        help='Filter components by name')
    parser.add_argument(
        '--filter-publisher',
        nargs='+',
        help='Filter components by publisher')
    parser.add_argument(
        '--filter-version',
        nargs='+',
        help='Filter components by version')
    parser.add_argument(
        '--filter-description',
        nargs='+',
        help='Filter components by description')
    parser.add_argument(
        '--filter-external',
        nargs='+',
        help='Filter out external references by matching URL substring'
    )

    args = parser.parse_args()

    filters = {
        'type': args.filter_type,
        'name': args.filter_name,
        'publisher': args.filter_publisher,
        'version': args.filter_version,
        'description': args.filter_description,
        'external': args.filter_external
    }

    deidentify_sbom(
        args.input,
        args.output,
        args.replacement,
        args.output_format,
        filters)
    print(f"De-identified SBOM written to {args.output}")


if __name__ == '__main__':
    main()

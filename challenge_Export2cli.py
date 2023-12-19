import os
import shutil
import yaml
import argparse
from collections import OrderedDict

def represent_dict_order(dumper, data):
    """Represent dictionary items in a specific order in YAML."""
    return dumper.represent_mapping(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, data.items())

yaml.add_representer(OrderedDict, represent_dict_order)

def remove_empty_fields(challenge):
    """Remove fields that are empty or set to null."""
    return {k: v for k, v in challenge.items() if v not in [None, "", [], {}]}

def order_challenge_keys(challenge):
    """Order keys of the challenge according to CTFd CLI's expected order."""
    key_order = [
        "name", "author", "category", "description", "value",
        "type", "extra", "image", "protocol", "host",
        "connection_info", "healthcheck", "attempts", "flags",
        "files", "topics", "tags", "hints",
        "requirements", "state", "version",
    ]
    ordered_challenge = OrderedDict()
    for key in key_order:
        if key in challenge:
            ordered_challenge[key] = challenge[key]
    return ordered_challenge

def ensure_required_fields(challenge):
    """Ensure the presence of required fields and set default author if missing."""
    required_fields = ["name", "category", "description", "value", "type"]
    for field in required_fields:
        if field not in challenge:
            return None  # Skip challenge if a required field is missing

    if "author" not in challenge:
        challenge["author"] = "OS_Master"

    return challenge

class CTFdExporter:
    def __init__(self, export_dir, output_dir):
        self.export_dir = export_dir
        self.output_dir = output_dir

    def convert(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        skipped_challenges = []  # List to store names of skipped challenges
        with open(os.path.join(self.export_dir, 'export.yaml'), 'r') as yaml_file:
            challenges = yaml.load_all(yaml_file, Loader=yaml.FullLoader)

            for challenge in challenges:
                if 'category' in challenge and 'name' in challenge:
                    category = challenge['category']
                    challenge_name = challenge['name']

                    challenge = remove_empty_fields(challenge)
                    challenge = ensure_required_fields(challenge)
                    if challenge is None:
                        skipped_challenges.append(challenge_name)
                        continue  # Skip to the next challenge

                    challenge_dir = os.path.join(self.output_dir, category, challenge_name)
                    os.makedirs(challenge_dir, exist_ok=True)

                    challenge = order_challenge_keys(challenge)
                    with open(os.path.join(challenge_dir, 'challenge.yml'), 'w') as challenge_yaml_file:
                        yaml.dump(challenge, challenge_yaml_file)

                    if 'files' in challenge:
                        for file_path in challenge['files']:
                            src_path = os.path.join(self.export_dir, file_path)
                            dest_path = os.path.join(challenge_dir, 'files', os.path.basename(file_path))

                            if not os.path.exists(os.path.join(challenge_dir, 'files')):
                                os.makedirs(os.path.join(challenge_dir, 'files'), exist_ok=True)

                            shutil.copy2(src_path, dest_path)

        # Print skipped challenges
        if skipped_challenges:
            print("Skipped challenges due to missing required fields:")
            for skipped_challenge in skipped_challenges:
                print(skipped_challenge)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Export CTFd challenges into the ctfd-cli format.")
    parser.add_argument("export_dir", help="Path to the CTFd_export directory")
    parser.add_argument("output_dir", help="Parent directory for the 'challenges' directory")
    args = parser.parse_args()

    exporter = CTFdExporter(args.export_dir, os.path.join(args.output_dir, "challenges"))
    exporter.convert()

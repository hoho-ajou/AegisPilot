import yaml


def load_config():
    with open("config/defaults.yaml") as f:          # shipped with the repo, never user input
        return yaml.load(f, Loader=yaml.SafeLoader)


if __name__ == "__main__":
    print(load_config())

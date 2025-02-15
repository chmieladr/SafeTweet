import secrets

# Set the way of rendering values in the .env file here
config = {
    "SECRET_KEY": secrets.token_hex(32)
}

# Set the path to the .env file here (default: '.env')
path = '.env'


def to_title(snake_case: str) -> str:
    return snake_case.replace("_", " ").title()


if __name__ == "__main__":
    # Preparing the .env file
    with open(path, "w") as dot_env:
        for key, value in config.items():
            dot_env.write(f"{key}={value}\n")

from client import ClientRequest

if __name__ == '__main__':
    client = ClientRequest()

    # Example usage with token query agent
    client.chat("Bitcoin Price today right now")

    # Example usage with general chat agent
    # client.chat("Hello")
    # client.chat("What's the date today")

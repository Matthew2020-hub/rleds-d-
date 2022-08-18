import uvicorn

if __name__ == "__main__":
    uvicorn.run('dev.asgi:application', reload=True)
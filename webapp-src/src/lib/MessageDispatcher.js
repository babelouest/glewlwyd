class MessageDispatcher {
	constructor() {
    this.subscriberList = {};
  }
  
  subscribe(name, cb) {
    this.subscriberList[name] = cb;
  }
  
  sendMessage(dest, message) {
    if (!Array.isArray(dest)) {
      dest = [dest];
    }
    if (dest[0] === "broadcast") {
      // Broadcast message
      this.subscriberList.forEach((subscriberCb, name) => {
        subscriberCb({type: "broadcast", message: message});
      });
    } else {
      for (var name in this.subscriberList) {
        if (dest.indexOf(name) >= 0) {
          this.subscriberList[name](message);
        }
      }
    }
  }
}

let messageDispatcher = new MessageDispatcher();

export default messageDispatcher;

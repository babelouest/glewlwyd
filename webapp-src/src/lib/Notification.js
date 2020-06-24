import React, { Component } from 'react';

import messageDispatcher from './MessageDispatcher';

class Notification extends Component {
  constructor(props) {
    super(props);
    this.state = {
      message: [],
      counter: 0,
      loggedIn: props.loggedIn
    }

    messageDispatcher.subscribe('Notification', (message) => {
      if (message.type) {
        var myMessage = this.state.message;
        myMessage.push({type: message.type, message: message.message, id: this.state.counter});
        this.setState({message: myMessage, counter: this.state.counter+1}, () => {
          this.timeoutClose(this.state.counter-1);
        });
      }
    });
    
    this.close = this.close.bind(this);
    this.timeoutClose = this.timeoutClose.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      loggedIn: nextProps.loggedIn
    });
  }

  timeoutClose(id) {
    setTimeout(() => {
      this.close(id);
//    }, 5000);
    }, 150000);
  }
  
  close(id) {
    var myMessages = this.state.message;
    myMessages.forEach((message, index) => {
      if (message.id === id) {
        myMessages.splice(index, 1);
        this.setState({message: myMessages});
      }
    });
  }
  
  render() {
    var toast = [];
    if (this.state.loggedIn) {
      this.state.message.forEach((message, index) => {
        var badge;
        if (message.type === "success") {
          badge = 
            <strong className="mr-auto">
              <span className="badge badge-success btn-icon">
                <i className="fas fa-check-circle"></i>
              </span>
              Glewlwyd
            </strong>
        } else if (message.type === "danger") {
          badge = 
            <strong className="mr-auto">
              <span className="badge badge-danger btn-icon">
                <i className="fas fa-exclamation-circle"></i>
              </span>
              Glewlwyd
            </strong>
        } else if (message.type === "warning") {
          badge = 
            <strong className="mr-auto">
              <span className="badge badge-warning btn-icon">
                <i className="fas fa-exclamation-circle"></i>
              </span>
              Glewlwyd
            </strong>
        } else { // info
          badge = 
            <strong className="mr-auto">
              <span className="badge badge-info btn-icon">
                <i className="fas fa-info-circle"></i>
              </span>
              Glewlwyd
            </strong>
        }
        toast.push(
          <div className="toast-container" style={{top: (85 + (index * 90)), right: 5}} key={index}>
            <div className="toast" role="alert" aria-live="assertive" aria-atomic="true">
              <div className="toast-header">
                {badge}
                <button type="button" className="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close" onClick={() => this.close(message.id)}>
                  <span aria-hidden="true">&times;</span>
                </button>
              </div>
              <div className="toast-body">
                {message.message}
              </div>
            </div>
          </div>
        );
      });
    }
    /*return (
      <div>
        {toast}
      </div>
    );*/
    return (
      <div aria-live="polite" aria-atomic="true">
        <div style={{position: "absolute", top: 0, right: 0}}>
          <div className="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div className="toast-header">
              <img src="..." className="rounded mr-2" alt="..."/>
              <strong className="mr-auto">Bootstrap</strong>
              <small className="text-muted">just now</small>
              <button type="button" className="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close">
                <span aria-hidden="true">&times;</span>
              </button>
            </div>
            <div className="toast-body">
              See? Just like this.
            </div>
          </div>

          <div className="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div className="toast-header">
              <img src="..." className="rounded mr-2" alt="..."/>
              <strong className="mr-auto">Bootstrap</strong>
              <small className="text-muted">2 seconds ago</small>
              <button type="button" className="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close">
                <span aria-hidden="true">&times;</span>
              </button>
            </div>
            <div className="toast-body">
              Heads up, toasts will stack automatically
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default Notification;

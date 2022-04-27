import React, { Component } from 'react';

import messageDispatcher from './MessageDispatcher';

class Notification extends Component {
  constructor(props) {
    super(props);
    this.state = {
      message: [],
      counter: 0
    }

    messageDispatcher.subscribe('Notification', (message) => {
      if (message.type) {
        var myMessage = this.state.message;
        myMessage.push({type: message.type, message: message.message, id: this.state.counter});
        this.setState({message: myMessage, counter: this.state.counter+1}, () => {
          var autohide = message.autohide;
          if (autohide === undefined) {
            autohide = true;
          }
          $("#toast-"+(this.state.counter-1)).toast({animation: true, autohide: autohide, delay: 5000}).toast('show');
        });
      }
    });
    
    this.close = this.close.bind(this);
  }
  
  static getDerivedStateFromProps(props, state) {
    return props;
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
    this.state.message.forEach((message, index) => {
      var icon;
      if (message.type === "success") {
        icon = <i className="fa fa-check-square-o text-success btn-icon"></i>;
      } else if (message.type === "danger") {
        icon = <i className="fa fa-exclamation-circle text-danger btn-icon"></i>;
      } else if (message.type === "warning") {
        icon = <i className="fa fa-exclamation-triangle text-warning btn-icon"></i>;
      } else { // info
        icon = <i className="fa fa-info-circle btn-icon text-info"></i>;
      }
      toast.push(
        <div className="toast" role="alert" aria-live="assertive" aria-atomic="true" key={index} id={"toast-"+message.id}>
          <div className="toast-header">
            {icon}
            <strong className="mr-auto">Glewlwyd</strong>
            <button type="button" className="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close" onClick={(e) => this.close(message.id)}>
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div className="toast-body">
            {message.message}
          </div>
        </div>
      );
    });
    return (
      <div className="position-fixed" style={{top: 45, right: 20, zIndex: 9999}}>
        {toast}
      </div>
    );
  }
}

export default Notification;

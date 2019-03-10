import React, { Component } from 'react';

import messageDispatcher from './MessageDispatcher';

class Notification extends Component {
  constructor(props) {
    super(props);
    this.state = {
      show: false,
      type: "",
      message: ""
    }

    messageDispatcher.subscribe('Notification', (message) => {
      if (message.type) {
        this.setState({show: true, type: message.type, message: message.message}, () => {
          setTimeout(() => {
            this.setState({show: false});
          }, 5000);
        });
      }
    });
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      show: false,
      type: "",
      message: ""
    });
  }
  
  render() {
    return (
      <div className={"alert alert-dismissible fade alert-" + this.state.type + (this.state.show?" show":"")} role="alert">
        {this.state.message}
        <button type="button" className="close" data-dismiss="alert" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
    );
  }
}

export default Notification;

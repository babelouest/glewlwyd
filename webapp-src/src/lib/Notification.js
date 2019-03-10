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
    if (this.state.show) {
      return (
        <div class={"alert alert-dismissible fade show alert-" + this.state.type} role="alert">
          {this.state.message}
          <button type="button" class="close" data-dismiss="alert" aria-label="Close">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>
      );
    } else {
      return ("");
    }
  }
}

export default Notification;

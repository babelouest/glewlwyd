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
    this.close = this.close.bind(this);
  }
  
  close() {
    this.setState({show: false});
  }

  componentWillReceiveProps(nextProps) {
  }
  
  render() {
    if (this.state.show) {
    return (
      <div style={{position: "absolute", top: 85, right: 5, borderWidth: "1px", borderStyle: "solid", borderRadius: "5px", padding: "5px"}}>
        <div className="toast" role="alert" aria-live="assertive" aria-atomic="true">
          <div className="toast-header">
            <svg className="bd-placeholder-img rounded mr-2" width="20" height="20" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice" focusable="false" role="img"><rect width="100%" height="100%" fill="#007aff"></rect></svg>
            <strong className="mr-auto">Glewlwyd</strong>
            <button type="button" className="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close" onClick={this.close}>
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div className="toast-body">
            {this.state.message}
          </div>
        </div>
      </div>
    );
    } else {
      return ("");
    }
  }
}

export default Notification;

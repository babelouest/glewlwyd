import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class SchemePage extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      type: props.type,
      name: props.name
    }
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      type: nextProps.type,
      name: nextProps.name
    });
  }
  
  render() {
    console.log(this.state);
    return (
      <div>grut</div>
    );
  }
}

export default SchemePage;

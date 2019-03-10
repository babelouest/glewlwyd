import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

import MockSchemeForm from './scheme/MockSchemeForm';

class SchemeAuthForm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scheme: props.scheme,
      currentUser: props.currentUser
    };
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser
    });
  }
  
  render() {
    if (this.state.scheme.scheme_type === "mock") {
      return (<MockSchemeForm config={this.state.config} scheme={this.state.scheme} currentUser={this.state.currentUser}/>);
    } else {
      return ("");
    }
  }
}

export default SchemeAuthForm;

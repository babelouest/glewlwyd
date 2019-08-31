import React, { Component } from 'react';

class Message extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      message: props.message
    }

    this.closeModal = this.closeModal.bind(this);
  }

  UNSAFE_componentWillReceiveProps(nextProps) {
    this.setState({
      title: nextProps.title,
      message: nextProps.message
    });
  }

  closeModal(e, result) {
    $("#messageModal").modal("hide");
  }
  
	render() {
    var messageJsx = [];
    if (this.state.message) {
      this.state.message.forEach((message, index) => {
        messageJsx.push(<li key={index}>{message}</li>);
      });
    }
		return (
    <div className="modal fade" id="messageModal" tabIndex="-1" role="dialog" aria-labelledby="messageModalLabel" aria-hidden="true">
      <div className="modal-dialog" role="document">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title" id="messageModalLabel">{this.state.title}</h5>
            <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeModal(e, false)}>
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div className="modal-body">
            <ul>
              {messageJsx}
            </ul>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("modal.close")}</button>
          </div>
        </div>
      </div>
    </div>
		);
	}
}

export default Message;
